# Phase 7 — Tests, dead code, tracking

Hygiene work: backfill missing test coverage, remove `#[allow(dead_code)]`
markers that mask integration gaps, track upstream features.

---

## Fix #39 — Track `gen` block stabilization

### Problem

`Cargo.toml:42` reserves a `nightly` feature; SPEC §6.3 promises `gen`-block-based
iteration when stable. As of this writing (2026-05-01), `gen` blocks are not yet
stable on Rust 1.85+ but are progressing toward `1.90`-ish.

### Plan

**Files:** `plans/upstream-tracking.md` (new)

1. Create a tracking doc `plans/upstream-tracking.md`:

   ```markdown
   # Upstream Rust feature tracking

   ## `gen` blocks (Iterator generator syntax)
   - **RFC**: https://rust-lang.github.io/rfcs/3513-gen-blocks.html
   - **Tracking issue**: rust-lang/rust #117078
   - **Stabilization PR**: TBD
   - **Action when stable**: Implement `Capture::packets_gen` per SPEC §6.3.
   - **Last checked**: 2026-05-01 — still nightly.

   ## `LendingIterator` / GAT iteration
   - **Status**: not on track for stabilization.
   - **Workaround in netring**: `PacketBatch<'a>` + `BatchIter<'a>` is the spec.

   ## XDP RX metadata extensions
   - **Kernel**: 6.0+ via `BPF_PROG_TYPE_XDP` with `xdp_metadata_ops`.
   - **Action**: implement `XdpPacket::timestamp()` once the metadata API
     stabilizes. Currently returns `None`.
   ```

2. Add a CI job (or just a comment in the README) to recheck this file every
   release cycle.

### Tests

None.

### Checklist
- [ ] Create tracking doc
- [ ] Note review cadence in CONTRIBUTING.md (if it exists; otherwise add a note
      in CHANGELOG release process)

---

## Fix #40 — Test coverage for AF_XDP, Bridge, async, eBPF

### Problem

`tests/` has no integration tests for AF_XDP, Bridge, or eBPF attachment. The
TX-only AF_XDP bug (#1) survived because the example was never run end-to-end.

### Plan

Bundle this with the relevant feature PRs (already noted in #1, #2, #15, #34, #44),
plus standalone:

**New files:**

### `tests/xdp.rs` (gated `integration-tests + af-xdp`)

Beyond the tests in #1 and #13:
- `xdp_statistics_after_burst` (paired with Fix #14)
- `xdp_shared_umem_two_queues` (Fix #32)
- `xdp_recv_batch_zero_copy` (Fix #13)

### `tests/bridge.rs` (gated `integration-tests`)

- `bridge_idle_does_not_busy_loop` (Fix #2)
- `bridge_forwards_known_payload` (Fix #2)
- `bridge_drops_oversize_increments_stat` (Fix #15)
- `bridge_into_inner_yields_handles` (Fix #35)

### `tests/eintr.rs` (gated `integration-tests`)

Already specified in Fix #6.

### `tests/timeout.rs` (gated `integration-tests`)

- `packets_for_terminates_on_idle_iface` (Fix #28)

### `tests/ebpf.rs` (gated `integration-tests + ebpf`)

Add an `ebpf` feature for these tests with `aya` as a dev-dependency:

```toml
[dev-dependencies]
aya = { version = "0.13", optional = true }

[features]
ebpf-test = ["aya"]
```

Tests:
- `attach_ebpf_filter_drops_unmatched` — load a tiny eBPF program that returns 0
  for non-IPv4 and the snaplen for IPv4, verify only IPv4 packets reach the
  capture.

This requires `aya` runtime and BPF support; gate behind `ebpf-test` so default
CI doesn't try.

### `tests/helpers.rs` extensions

```rust
// veth pair management
pub fn paired_veth(name_a: &str, name_b: &str) -> Result<VethGuard, io::Error> { ... }

// AF_XDP capability probe
pub fn xdp_compatible_iface() -> Option<String> { ... }

// Process-wide unique port (already exists)
pub fn unique_port() -> u16 { ... }

// Test that runs only with CAP_NET_ADMIN (skips otherwise)
pub fn require_cap_net_admin() -> Result<(), &'static str> { ... }
```

### CI updates

Add a job to `.github/workflows/`:

```yaml
- name: integration tests (AF_PACKET)
  run: |
    cargo test --features integration-tests,tokio,channel --no-run
    sudo setcap cap_net_raw,cap_net_admin+ep $(...)
    cargo test --features integration-tests,tokio,channel
```

For AF_XDP integration testing on CI, may require a privileged runner or a
custom Linux kernel with XDP enabled on `lo` (kernel ≥ 5.4 supports it
out of the box).

### Checklist
- [ ] `tests/xdp.rs`
- [ ] `tests/bridge.rs`
- [ ] `tests/eintr.rs`
- [ ] `tests/timeout.rs`
- [ ] `tests/ebpf.rs`
- [ ] Helper extensions (veth, xdp probe)
- [ ] CI workflow updates
- [ ] CHANGELOG entry under "Added (tests)"

---

## Fix #41 — Remove `#[allow(dead_code)]` on `MmapRing::block_size`

### Problem

`src/afpacket/ring.rs:103-106`:

```rust
#[allow(dead_code)]
pub(crate) fn block_size(&self) -> usize {
    self.block_size
}
```

Either it has a use case or it should be deleted.

### Plan

**Files:** `src/afpacket/ring.rs`, possibly callers

1. Audit: nothing in-tree uses it.
2. Remove the method entirely. If a caller materializes during phase 3 (e.g., a
   diagnostic helper for `XdpSocket`), reintroduce.

### Checklist
- [ ] Delete `MmapRing::block_size`
- [ ] Confirm clippy clean
- [ ] CHANGELOG entry under "Changed (internal)"

---

## Fix #42 — Use `XdpRing::needs_wakeup`

### Problem

`src/afxdp/ring.rs:181-183`:

```rust
#[allow(dead_code)] // available for flush() optimization
pub(crate) fn needs_wakeup(&self) -> bool { ... }
```

### Plan

Already specified in Fix #33. Once that lands, remove the `#[allow(dead_code)]`.

### Checklist
- [ ] Bundled with Fix #33
- [ ] Confirm clippy clean

---

## Fix #43 — Use `attach_fanout_ebpf`

### Problem

`src/afpacket/fanout.rs:39-51`:

```rust
#[allow(dead_code)]
pub(crate) fn attach_fanout_ebpf(...) -> Result<(), Error> { ... }
```

### Plan

Already specified in Fix #8. Once that lands, remove the `#[allow(dead_code)]`.

### Checklist
- [ ] Bundled with Fix #8
- [ ] Confirm clippy clean

---

## Cross-cutting cleanup

### After all phases land

1. **`#[deny(unsafe_op_in_unsafe_fn)]`** — already set in `lib.rs:2`. After the
   refactors verify no new unsafe-fn bodies introduce implicit unsafe.

2. **Miri** — add `cargo miri test` to `just ci`:

   ```just
   ci-miri:
       cargo +nightly miri test --features tokio,channel
   ```

   Several of the unsafe-heavy modules (`packet.rs::BatchIter`, `afxdp::ring`,
   `capture.rs::PacketIter` after Fix #4) benefit from Miri's strict-provenance
   checking. Disable for tests touching real syscalls (Miri can't run them).

3. **`cargo deny`** in CI for license / advisory checks.

4. **`cargo machete`** in CI to catch unused deps as the dependency surface
   grows (pcap-file, metrics, aya).

5. **`cargo public-api`** — once 0.3.0 is cut, lock the public API to prevent
   accidental breaking changes:

   ```toml
   # .github/workflows/public-api.yml
   - run: cargo public-api --diff-git-checkouts main HEAD
   ```

### Checklist
- [ ] Miri CI job
- [ ] cargo-deny CI job
- [ ] cargo-machete CI job
- [ ] cargo-public-api CI job after 0.3.0
- [ ] CONTRIBUTING.md (if creating it) documents the CI matrix
