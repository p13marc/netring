# netring — AF_XDP RX hardware metadata + timestamps (plan)

> **Status:** plan, 2026-06-16. Candidate feature; no fixed release slot.
> **flowscope touch** (we own it): `PacketView` gains optional metadata fields.
> Additive where possible; the `PacketView` field additions are the one small
> flowscope break worth taking, deferred/absorbed per Arch §7.

## 1. Why

Kernel 6.3+ exposes [XDP-hints kfuncs](https://docs.kernel.org/networking/xdp-rx-metadata.html)
that hand AF_XDP consumers **hardware RX timestamp, RX hash (+ hash type), VLAN
tag, and checksum status** per frame. **No Rust library surfaces these** — and a
NIC-accurate hardware timestamp is gold for latency analysis, forensics, and
precise capture ordering. There's already a `// AF_XDP doesn't surface metadata …
not yet wired` TODO in our recv path. Small, unique, high-value differentiator.

## 2. Design

### The mechanism (confirmed)
- The kfuncs (`bpf_xdp_metadata_rx_timestamp`, `bpf_xdp_metadata_rx_hash`,
  `bpf_xdp_metadata_rx_vlan_tag`) are called **inside the XDP program**, which
  uses `bpf_xdp_adjust_meta()` to reserve space and writes a struct into
  `ctx->data_meta` (the bytes immediately *before* `data`). Userspace reads that
  struct at a fixed negotiated offset before the payload.
- **Gotcha (must handle):** the metadata area is **not zeroed** — it can hold
  stale garbage. Drivers return `-EOPNOTSUPP` (kfunc unimplemented) or `-ENODATA`
  (no value this frame). So the program **must write a validity bitmask**; the
  consumer must trust only flagged fields.

### Vendored program
- Extend `redirect_all` (and `filter_redirect`) — or add a `redirect_meta`
  variant — to, before redirecting: `bpf_xdp_adjust_meta(ctx, -sizeof(meta))`,
  call each kfunc, and write `struct netring_xdp_meta { u32 valid_flags; u64
  rx_timestamp; u32 rx_hash; u32 rx_hash_type; u32 vlan_tci; u32 vlan_proto; }`
  into `data_meta`. CO-RE / `__weak` kfunc decls so it loads on kernels/drivers
  lacking some kfuncs (relocated to no-ops).
- Reserve matching UMEM **headroom** so the metadata fits before each frame
  (`xdp_umem_reg.headroom`). Keep the metadata size fixed + versioned (`valid_flags`
  high bit = layout version) so the BPF↔userspace contract is explicit.

### Userspace / netring
- `XdpSocket`/`XdpCapture` read the `netring_xdp_meta` struct from each frame's
  headroom on RX, gated by `valid_flags`.
- `XdpCapture::rx_metadata() -> RxMetaSupport { timestamp, hash, vlan }` — a probe
  (built by attempting the kfuncs at load / reading the first valid frame) so
  callers know what the driver actually provides.
- **flowscope `PacketView`:** add **one cohesive, strongly-typed**
  `rx_meta: RxMetadata` (not four loose `Option`s — cohesion + one branch):
  ```rust
  pub struct RxMetadata {
      pub hw_timestamp: Option<Timestamp>,            // None ⇒ driver gave -ENODATA
      pub rx_hash: Option<RxHash>,                    // RxHash { value: u32, ty: RssHashType }
      pub vlan: Option<VlanTag>,                      // VlanTag { tci: u16, proto: VlanProto }
      pub checksum: ChecksumStatus,                   // enum Unknown|Unnecessary|Complete(u16)|None
  }
  ```
  Per-field `Option` mirrors the kfunc `-EOPNOTSUPP`/`-ENODATA` reality (a NIC may
  give hash but not timestamp). `Default` = all-absent, so existing `PacketView`
  construction keeps compiling; netring fills it from the metadata struct, leaves
  default on AF_PACKET (until `SO_TIMESTAMPING`) and COPY/generic XDP.
  `RssHashType`/`VlanProto`/`ChecksumStatus` are enums, not raw ints (strong typing).
- The Monitor's per-packet `ts` prefers `rx_meta.hw_timestamp` when present → flow
  records + EVE get NIC-accurate timing. `rx_meta.rx_hash` is a free flow-key
  accelerator (the NIC already hashed the 5-tuple) — an optional tracker fast-path.

## 3. flowscope side
`PacketView` gains the optional metadata fields above + the `RssHashType` /
`VlanTag` / `ChecksumStatus` enums. This is the only flowscope break — minor,
additive fields with `Option`/`Default`, so existing `PacketView` construction
keeps compiling. Publish flowscope, then netring `cargo update --precise`.

## 4. Milestones
- **M1** flowscope `PacketView` metadata fields + enums (publish).
- **M2** the `redirect_meta` XDP program (vendored `.c`/`.o`, CO-RE kfunc decls,
  validity flags) + UMEM headroom reservation.
- **M3** userspace read + `RxMetaSupport` probe + populate `PacketView` + Monitor
  `ts` preference.
- **M4** root-gated `lo` test (generic XDP on lo → kfuncs `-ENODATA` → exercises
  the **degrade path**: `valid_flags == 0`, software ts fallback) + a `veth` test
  if veth supports the kfuncs in the CI kernel.
- **M5** docs (driver support matrix: ice/mlx5/gve; the not-zeroed gotcha) +
  example (per-packet HW timestamp printer).

## 5. Testing
- CI (`lo`, generic XDP) validates the **degrade path** only — real timestamps
  need an ice/mlx5/gve NIC. State that plainly; recruit real-NIC validation.
- Unit: the `valid_flags` parsing + the `RxMetaSupport` probe with synthetic
  metadata bytes (incl. the garbage-when-invalid case).
- dhat Δ0: the metadata read is a fixed struct copy from headroom — keep it off
  the per-packet alloc path (read into a stack struct, no `Vec`).

## 6. Risks & open decisions
- **Driver coverage is uneven** — ice/mlx5 have timestamp+hash; many NICs have
  none. The probe + graceful degrade are mandatory; never assume availability.
- **Metadata layout contract** — version it (`valid_flags` high bit) so a future
  field addition doesn't silently misparse old programs.
- **TX metadata** (timestamps on egress, kernel 6.8+) is a natural sibling but
  out of scope here — note it for a follow-up.
- **Open:** also wire AF_PACKET `SO_TIMESTAMPING` (hardware/PHC timestamps on the
  AF_PACKET path) so `hw_timestamp` isn't AF_XDP-only? Recommend a follow-up;
  keep this plan AF_XDP-focused.
