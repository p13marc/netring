# eBPF-accelerated bandwidth — design + spike plan (0.22 §6, status: DESIGNED)

> **Status.** This is the design + spike plan for moving `bandwidth_by_app`
> accounting into the kernel. It is **not shipped**: the payoff is a perf
> ceiling that can only be validated on a real multi-Gbps NIC, so the
> implementation is **gated on measurement** (a focused session with hardware).
> The shipped 0.22 path is the userland recorder (`on_bandwidth`, an
> `on_ctx::<FlowPacket>` handler feeding a `RollingRate`).

## Why

The userland recorder does one `RollingRate::record` per packet on the Rust
dispatch path. It's zero-alloc and fine at moderate rates, but at 10–40 Gbps the
per-packet Rust work becomes the bottleneck and packets drop. The established
fix (Cilium/Hubble) is to **account bytes in the kernel** with a single per-CPU
BPF-map update per packet, and read the aggregate from userspace on a slow
cadence. The user-facing API (`on_bandwidth` + `BandwidthReport`) is unchanged —
only the *producer* of the bytes-per-app numbers moves.

## Architecture

```
        ┌───────────────── kernel ─────────────────┐     ┌──── userland ────┐
RX ───► │ XDP: parse 5-tuple, acc_map[key] += len  │ ──► │ every report tick:│
        │      (per-CPU hash; no atomics needed)    │     │  iterate acc_map, │
        └───────────────────────────────────────────┘    │  sum PerCpuValues,│
                                                          │  key→app_label,   │
                                                          │  → BandwidthReport│
                                                          └───────────────────┘
```

netring already vendors a redirect-all XDP program loaded via `aya`
(`src/afxdp/loader/`). The accounting either **extends** that program (count,
then redirect) or ships as a sibling program attached to the same hook.

## Kernel side (BPF, C → vendored `.o`)

```c
struct flow_key {                 // ABI: must match the Rust #[repr(C)] mirror
    __u8  proto;                  // IPPROTO_TCP / UDP / ICMP
    __u8  _pad[3];
    __be32 saddr, daddr;
    __be16 sport, dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);   // per-CPU: each core owns its slot
    __type(key, struct flow_key);
    __type(value, __u64);                     // bytes
    __uint(max_entries, 1 << 16);
} acc_map SEC(".maps");

SEC("xdp")
int account(struct xdp_md *ctx) {
    struct flow_key k = {0};
    __u64 len;
    /* bounds-checked parse of eth→ip(v4/v6)→l4 into k + len; bail on non-IP */
    __u64 *b = bpf_map_lookup_elem(&acc_map, &k);
    if (b) *b += len;                          // per-CPU slot → plain add, no atomic
    else   bpf_map_update_elem(&acc_map, &k, &len, BPF_ANY);
    return XDP_PASS; /* or the existing redirect */
}
```

Notes:
- **Per-CPU maps need no atomics** — each CPU writes its own copy of the value;
  userspace sums them. This is what lets the kernel path scale linearly with
  cores (Cilium's `acc_map` accounting pattern).
- Consider `BPF_MAP_TYPE_LRU_PERCPU_HASH` so stale flows self-evict under the
  `max_entries` cap instead of the map filling up.
- The vendored `.o` regen needs `clang` with the BPF target — per
  `netring/CLAUDE.md`, only the maintainer touches the vendored bytecode.

## Userland side (aya)

On each report cadence (not per packet):

```rust
// acc_map opened as a PerCpuHashMap<_, FlowKey, u64> via Ebpf::map / take_map.
let mut per_app: HashMap<&'static str, u64> = HashMap::new();
for key in acc_map.keys() {
    let key = key?;
    let per_cpu: PerCpuValues<u64> = acc_map.get(&key, 0)?; // one u64 per CPU
    let bytes: u64 = per_cpu.iter().copied().sum();          // ← aggregate
    let label = five_tuple_from(key).app_label_with(table);  // key → app, userland
    *per_app.entry(label).or_default() += bytes;
}
// feed per_app deltas into the existing RollingRate / BandwidthReport.
```

- aya exposes `HashMap`, `PerCpuHashMap`, `PerCpuArray`; a per-CPU read returns
  `PerCpuValues` (a slice, one entry per CPU) that userspace **sums**.
- `app_label` mapping is done **userland** on readout (the kernel only keys by
  raw 5-tuple), reusing the existing `LabelTable`.
- Interval bytes = difference vs the previous read (or use the LRU map +
  periodic clear). Per-packet Rust work is now **zero** — the dhat Δ0 invariant
  is trivially held.

## API (the R4 seam — ships *with* the XDP backend, not before)

```rust
#[non_exhaustive]
pub enum BandwidthBackend { Userland /* default */, #[cfg(feature = "xdp-loader")] Xdp }
impl MonitorBuilder { pub fn bandwidth_backend(self, b: BandwidthBackend) -> Self; }
```

`BandwidthReport` reads from whichever backend; the typed view is identical. The
enum is `#[non_exhaustive]` so adding `Xdp` later is non-breaking — which is why
the seam is deferred to land *with* `Xdp` rather than shipping a hollow
one-variant enum now.

## ABI ownership

`flow_key` (the C struct + its Rust `#[repr(C)]` mirror) is a versioned ABI
between the BPF program and userspace. flowscope owns the flow/key model
(`FiveTupleKey`), so the canonical home for the program + key layout is
**flowscope** (0.15 wishlist: ship the program + a versioned map ABI); netring
loads + reads it. For the spike, prototype the key netring-side to get numbers,
then move it upstream if it ships.

## Spike methodology + decision gate (time-boxed ~1 week)

1. Prototype the program + the aya read loop behind `BandwidthBackend::Xdp`.
2. Measure on a **real multi-Gbps NIC** (not `lo`): packet-drop rate + CPU vs
   the `Userland` recorder under load. `SKB_MODE` works on `lo`/unprivileged but
   gives no perf benefit — the win is `DRV_MODE` on a native-driver NIC.
3. **Gate:** ship `Xdp` only if the delta is material *and* the portability cost
   (kernel version, `DRV` vs `SKB`, verifier acceptance) is acceptable.
   Otherwise: keep the userland path, record the numbers here, and revisit in
   0.23. Either outcome is a clean ship.

## Out of scope (0.23+)

Kernel-side TCP-RST (`SOCK_OPS`) and ICMP-error correlation maps — the same
"account/observe in the kernel, expose as typed events" pattern, but a separate
lift.

## References

- [Cilium BPF & XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/) —
  the per-CPU `acc_map` byte-accounting model (per-CPU maps eliminate lock
  contention, scale linearly with cores).
- [aya `maps` docs](https://docs.rs/aya/latest/aya/maps/index.html) —
  `PerCpuHashMap` / `PerCpuValues`, `Ebpf::map` / `take_map`.
