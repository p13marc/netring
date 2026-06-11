# netring 0.21 Phase G — `correlate` re-export cleanup

## 1. Summary

Delete `netring/src/correlate.rs`. Re-export from `flowscope::correlate` instead. flowscope 0.13.0's `new_unbounded` constructors match netring's existing 2-arg shape, so this is a zero-API-impact cleanup.

## 2. Status

Not started. Depends on Phase H.1 (flowscope 0.13.0 dep bump).

## 3. Prerequisites

- Phase H.1 — flowscope 0.13.0 in `Cargo.toml`.

## 4. Out of scope

- Changing the user-facing API. netring's existing call sites use `TimeBucketedCounter::new(window, bucket)` (2-arg). flowscope ships `new_unbounded(window, bucket)`; we re-export and switch the macro `new` → `new_unbounded` internally.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| Delete | `src/correlate.rs` | All primitives now upstream |
| Modify | `src/lib.rs` | `pub use flowscope::correlate;` |
| Modify | `src/monitor/mod.rs` | `MonitorBuilder::counter` calls `TimeBucketedCounter::new_unbounded` instead of `new` |
| Modify | `src/ctx/from_ctx.rs` | `CounterRegistry::register` accepts flowscope's type |
| Delete | `tests/correlate_*.rs` | Tests covered by flowscope's own suite; netring tests focus on integration |

## 6. API

### G.1 — Re-export

```rust
// src/lib.rs
pub use flowscope::correlate::{
    TimeBucketedCounter, TimeBucketedSet,
    KeyIndexed,
    BurstDetector, BurstHit,
    TopK,
    Ewma,
    SequencePattern, KeylessSequencePattern,
    FlowStateMap,  // bonus from flowscope 0.13.0 plan 154
};
```

### G.2 — Internal call site update

```rust
// src/monitor/mod.rs
pub fn counter<K>(mut self, window: Duration, bucket: Duration) -> Self
where K: std::hash::Hash + Eq + Clone + Send + 'static {
    self.counters.register::<K>(TimeBucketedCounter::new_unbounded(window, bucket));
    self
}
```

User-visible signature unchanged.

## 7. Implementation steps

1. After Phase H.1 lands flowscope 0.13.0, `git rm` `netring/src/correlate.rs`.
2. Add the `pub use flowscope::correlate::*` line to `lib.rs`.
3. Replace internal `TimeBucketedCounter::new` calls with `new_unbounded`.
4. Delete `tests/correlate_*.rs` (now covered upstream).
5. Run the full test suite; fix any callsites that imported from `netring::correlate::…` with the old path (likely zero, since flowscope's path is identical via the re-export).

## 8. Tests

- Existing integration tests pass unchanged.
- `cargo test --doc` confirms no broken intra-doc links.

## 9. Acceptance criteria

- `netring/src/correlate.rs` deleted.
- `cargo build` compiles all examples without code changes.
- Public API (`netring::correlate::TimeBucketedCounter`) resolves to flowscope's type.

## 10. Risks

- **R1 — Hidden trait re-implementations.** If netring's `correlate.rs` shipped a method that flowscope's doesn't (e.g., a custom `report()` helper), users break. Audit by reading netring's `correlate.rs` end-to-end; if there's no such method, this is risk-free. Spot check: flowscope's `TimeBucketedCounter::entries_above` matches netring's; flowscope's `KeyIndexed::drain_expired` matches netring's.
- **R2 — Capacity semantics for users who passed `usize::MAX`.** flowscope's hashbrown overflow fix (CHANGELOG plan 154) makes `new_unbounded` the right path for the netring use case (no cap). Confirmed safe.

## 11. Effort

- LoC delta: -800 (delete `correlate.rs`), +5 (re-export line). Net: ~-795 LoC.
- Time estimate: **~1 day**.

## 12. Provenance

- Round-1 wishlist §5.4 (absorb correlate primitives upstream) → shipped in flowscope 0.12.0 (plan 125).
- Round-1 wishlist §5.5 (SegmentBufferReassembler convenience) — flowscope already re-exports at crate root; no netring work needed.
- netring's `correlate.rs` predates flowscope's correlate module; this phase reverses the duplication.
