# Upstream + future-work tracking

Things waiting on rustc / kernel features, or deliberately deferred. Re-check
at each minor release and update the "Last checked" line.

---

## `gen` blocks (Iterator generator syntax)

- **RFC**: https://rust-lang.github.io/rfcs/3513-gen-blocks.html
- **Tracking issue**: rust-lang/rust #117078
- **Action when stable**: implement `Capture::packets_gen` per SPEC §6.3.
- **Cargo.toml** reserves the `nightly` feature for this.
- **Last checked**: 2026-05-05 — still nightly only.

## `LendingIterator` / GAT iteration in `Iterator`

- **Status**: not on track for stabilization.
- **Workaround in netring**: `PacketBatch<'a>` + `BatchIter<'a>` pair plus
  the `'static`-erasure trick in `Packets` (`src/afpacket/rx.rs`) and
  `AsyncCapture::try_recv_batch` (`src/async_adapters/tokio_adapter.rs`).
  When Polonius lands these workarounds simplify; until then they stay.
- **Last checked**: 2026-05-05.

## Polonius (NLL successor)

- **Tracking issue**: rust-lang/rust #43234
- **Affects**: `ReadableGuard::next_batch` and `AsyncCapture::try_recv_batch`
  use a raw-pointer split because stable's NLL can't see that the Some-arm
  borrow doesn't outlive the None-arm `clear_ready`. Polonius would handle
  the split natively; remove the unsafe blocks once it's stable on the MSRV.
- **Last checked**: 2026-05-05 — `-Znext-solver` previews but no
  stabilization ETA.

## XDP RX metadata extensions

- **Kernel**: 6.0+ via `BPF_PROG_TYPE_XDP` with `xdp_metadata_ops`.
- **Action**: implement `XdpPacket::timestamp()` (currently always returns
  `None`) and populate `OwnedPacket` metadata fields for AF_XDP origin.
  Both are documented as "not yet wired" and are forward-compatible.
- **Tracking**: kernel commit set around v6.0; userland integration still
  evolving (libxdp/aya have partial support).
- **Last checked**: 2026-05-05.

## High-level `SharedUmem` helper

- **Status**: low-level primitive shipped in 0.5.0
  (`XdpSocketBuilder::shared_umem(primary)` — sets `XDP_SHARED_UMEM` and
  passes the primary fd as `sxdp_shared_umem_fd`). Each socket still has
  its own private free-list; users must partition the UMEM range manually.
- **Action**: design and ship a higher-level helper that automates frame
  partitioning across primary + N secondaries, optionally with a shared
  allocator (Mutex-protected or partition-based). Wait for actual user
  code that demands it before settling the threading-model trade-offs.
- **Last checked**: 2026-05-05.

## Unified `PacketBackend` trait

- **Status**: deferred. AF_PACKET `Packet` exposes metadata
  (`direction`, `vlan_tci`, `rxhash`, `status`) that AF_XDP doesn't,
  so a unified trait would force `Option`-wrapped accessors and lose
  ergonomics. Most users pick one backend and stay there.
- **Action**: revisit when there's user code that demands cross-backend
  generic handling.
- **Last checked**: 2026-05-05.

## CI hardening (post-0.5)

- **Miri** — add `cargo +nightly miri test --features tokio,channel` to
  catch UB in the unsafe-heavy modules (`packet.rs::BatchIter`,
  `afxdp::ring`, `async_adapters::tokio_adapter`).
- **cargo-public-api** — pin the public API once 0.5 is stable, surface
  diffs on PRs.
- **Last checked**: 2026-05-05 — neither blocking, both nice-to-have.

## Review cadence

Each minor release: re-check the "Last checked" lines and update or remove
obsolete entries. When an item ships, port the implementation note into the
release CHANGELOG and remove its entry here.
