# Upstream tracking

Things waiting on rustc / kernel features. Re-check at each release cycle and
update the "Last checked" line.

---

## `gen` blocks (Iterator generator syntax)

- **RFC**: https://rust-lang.github.io/rfcs/3513-gen-blocks.html
- **Tracking issue**: rust-lang/rust #117078
- **Action when stable**: implement `Capture::packets_gen` per SPEC §6.3.
- **Cargo.toml** reserves the `nightly` feature for this.
- **Last checked**: 2026-05-01 — still nightly only.

## `LendingIterator` / GAT iteration in `Iterator`

- **Status**: not on track for stabilization.
- **Workaround in netring**: `PacketBatch<'a>` + `BatchIter<'a>` pair plus the
  `'static`-erasure trick in `PacketIter` (`src/capture.rs`) and
  `AsyncCapture::try_recv_batch` (`src/async_adapters/tokio_adapter.rs`). When
  Polonius lands these workarounds simplify; until then they stay.
- **Last checked**: 2026-05-01.

## Polonius (NLL successor)

- **Tracking issue**: rust-lang/rust #43234
- **Affects**: `ReadableGuard::next_batch` and `AsyncCapture::try_recv_batch`
  use a raw-pointer split because stable's NLL can't see that the Some-arm
  borrow doesn't outlive the None-arm `clear_ready`. Polonius would handle
  the split natively; remove the unsafe blocks once it's stable on the MSRV.
- **Last checked**: 2026-05-01 — `-Znext-solver` previews but no stabilization
  ETA.

## XDP RX metadata extensions

- **Kernel**: 6.0+ via `BPF_PROG_TYPE_XDP` with `xdp_metadata_ops`.
- **Action**: implement `XdpPacket::timestamp()` (currently always returns
  `None`) and populate `OwnedPacket` metadata fields for AF_XDP origin. Both
  are documented as "not yet wired" and are forward-compatible.
- **Tracking**: kernel commit set around v6.0; userland integration still
  evolving (libxdp/aya have partial support).
- **Last checked**: 2026-05-01.

## XDP shared UMEM

- **Kernel**: supported since the AF_XDP introduction; netring just doesn't
  expose it yet.
- **Action**: see Phase 3 plan, Fix #32 in `plans/fixes/03-afxdp-completeness.md`.
  Holds the multi-queue / multi-thread surface area; deferred until trait
  abstraction (Fix #31) lands so the plumbing fits the unified API.
- **Last checked**: 2026-05-01.

## Review cadence

Each minor release: re-check the "Last checked" lines and update or remove
obsolete entries. If an item ships, port the implementation note from this
file into a CHANGELOG entry.
