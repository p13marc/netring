# Performance (0.25)

netring's performance story has two halves that must not be conflated:

1. **Capture rate** — how fast frames cross from the kernel into userspace.
   This is dominated by the NIC, driver, ring sizing, and backend
   (AF_PACKET TPACKET_v3 vs AF_XDP). It is **hardware-gated** and is *not*
   measurable on loopback or in a sandbox.
2. **Userspace dispatch rate** — how fast netring processes each frame once
   read: flow tracking, L7 parsing, and event dispatch. This is the part
   netring *controls*, and it **is** measurable without a NIC.

This document gives reproducible numbers for (2), the methodology and tuning
levers for (1), and is explicit about which figures are pending real-NIC
measurement rather than quietly omitting them.

## What's measured, and where

| Metric | Harness | Needs hardware? | Status |
|---|---|---|---|
| Allocations / packet | `benches/zero_alloc.rs` (dhat) | no | **Δ 0 / 0 — enforced gate** |
| Userspace dispatch throughput | `benches/dispatch_throughput.rs` (criterion) | no | reproducible (below) |
| Timestamp / status decode | `benches/throughput.rs` (criterion) | no | reproducible |
| Kernel-side shedding (pushdown) | `tests/monitor_lo_kernel_pushdown.rs` | root, loopback | validated (CI) |
| Capture pps / Gbps / latency | live-NIC rig | **yes** | **pending real-NIC** |

### Zero-allocation invariant (enforced)

`cargo bench --features bench-zero-alloc --bench zero_alloc` profiles 100k
synthetic dispatches with dhat and asserts **Δ heap < 512 bytes / Δ blocks <
100**. Measured: **Δ 0 / 0** — the borrowed zero-copy run loop (0.24 Phase B)
does no per-packet allocation, and the 0.25 subscription/effect paths preserve
it (they're gated off when unused). This is the CI-enforced perf regression
gate: a per-packet allocation regression fails the build. (A *pps* regression
gate needs a real-NIC CI runner — see "Pending".)

### Userspace dispatch throughput (reproducible, cap-free)

`cargo bench --features flow --bench dispatch_throughput` tracks a fixed batch
of synthetic TCP/IPv4 frames (4096 frames across ~64 flows) through a flowscope
`Driver` — the per-frame cost the run loop pays *after* the zero-copy read.

Indicative result (single core, one dev machine; **your numbers will differ** —
re-run on your target):

```
dispatch/track_into_4096_frames_64_flows
    thrpt:  ~4.7 Melem/s        # ~4.7M frames/sec/core, flow tracking only
```

This is the userspace ceiling for the flow-tracking layer on one core: at 4.7
Mpps/core, an 8-core sharded deployment has ~37 Mpps of *tracking* headroom —
well above what a single 10GbE link delivers at typical packet sizes, so for
flow/L7 workloads the capture path (half 1) is the bottleneck, not dispatch.
L7 parsing (HTTP/TLS/DNS) adds per-message cost on top; benchmark your own
detector mix.

### Kernel-side shedding (pushdown), validated on loopback

`tests/monitor_lo_kernel_pushdown.rs` (CI, root) proves the 0.25 S1/S2 safe
fail-open kernel prefilter actually sheds traffic in the kernel: in one CI run
it sent 6472 matching + 64720 noise UDP frames and the kernel delivered only
the matching subset to userspace (`delivered < noise_sent`). Pushing the
subscription union's `{proto, port}` interest into the AF_PACKET socket (or the
AF_XDP `filter_redirect` map, 0.25 W1a) removes uninteresting traffic before it
costs a userspace cycle — the single biggest lever when you care about a narrow
slice of a busy link.

## Tuning levers

Ordered roughly by impact:

1. **Kernel pushdown** — narrow your subscriptions so the union prefilter sheds
   noise in-kernel (above). Free; the default.
2. **Per-CPU sharding + pinning** — `ShardedRunner::new(iface, FanoutMode::Cpu,
   group, n_cores, build)` opens one socket per core in a `PACKET_FANOUT` group;
   `.pin_cpus(true)` (0.25 C1) binds each shard thread to its core via
   `sched_setaffinity`, keeping flow state + RX ring + worker core-local. Pair
   with NIC IRQ affinity so queue `i` interrupts core `i`.
3. **Fanout mode & the symmetric-RSS pitfall** — `FanoutMode::Cpu` steers by the
   CPU servicing the IRQ (stable per-flow *if* RSS is symmetric).
   `FanoutMode::Hash` uses the kernel/NIC flow hash, which for many NICs is
   **not symmetric**: the two directions of one flow can land on different
   shards, splitting its state. If your detectors need both directions on one
   shard, either (a) use `FanoutMode::Cpu` with symmetric RSS configured on the
   NIC, or (b) attach a symmetric fanout program via `FanoutMode::Ebpf` +
   `Capture::attach_fanout_ebpf()` (an XOR-of-sorted-endpoints hash is
   symmetric by construction). See `docs/scaling.md`.
4. **AF_XDP** (`af-xdp`) — kernel-bypass RX into a UMEM. Use `DRV_MODE` on a
   NIC whose driver supports native XDP for zero-copy; `SKB_MODE` (the default)
   works everywhere but copies. `MonitorBuilder::xdp_interface_loaded` (0.25
   W1a) attaches the redirect program for you.
5. **Busy-poll trio** — `SO_PREFER_BUSY_POLL` + `SO_BUSY_POLL` +
   `SO_BUSY_POLL_BUDGET` (kernel ≥ 5.11) trade CPU for latency on
   payload-touching workloads.
6. **Ring sizing** — bigger blocks/frames reduce freezes under burst; watch
   `CaptureTelemetry.drops` / `.freezes` (`on_capture_stats`) to right-size.
7. **UMEM hugepages + NUMA** (`af-xdp`, 0.25 W4) — back the UMEM with
   `MAP_HUGETLB` and `mbind` it to the NIC's NUMA node to cut TLB misses and
   cross-node traffic.

## Micro-optimisation candidates (pending real-NIC harness)

Per-frame micro-opts (header/descriptor prefetch, batched AF_XDP fill-ring
refill) are deliberately **not** landed blind: each must show a net-positive
pps delta on a real NIC, which the sandbox (loopback only) cannot measure.
They're tracked as harness candidates — wire a real-NIC runner, baseline with
the recipe below, then land each only if it pays. `#[cold]` hints on error
paths are applied where extraction is clean (they're optimizer hints with no
validation needed).

## Pending: real-NIC capture numbers

These require a host with a real NIC (ideally multi-queue + XDP-capable) and a
load generator (TRex / `pktgen` / `iperf3`). The methodology:

1. Generate line-rate traffic at a fixed packet size (64B for pps ceiling,
   1500B for Gbps).
2. Run a minimal Monitor (`.interface(nic)` + one counting handler), record
   `CaptureTelemetry.packets` vs offered load → **capture pps** and the **drop
   onset** rate.
3. Repeat: AF_PACKET vs AF_XDP (copy vs zero-copy), 1 shard vs N-shard pinned,
   pushdown on vs off (quantifies lever #1).
4. Latency: hardware RX timestamps (`SO_TIMESTAMPING`) minus generator TX time.

When run, drop the numbers into the table at the top and a results section
here. Until then this section is intentionally a methodology, not a fabricated
figure — netring does not ship invented benchmarks.
