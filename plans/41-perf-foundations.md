# Plan 41 — Performance foundations

## Summary

Two optimizations that together target a 1.5–3× throughput
improvement on representative workloads:

1. **Zero-copy reassembly via `BytesMut` pool** — eliminate
   `Bytes::copy_from_slice` per TCP segment in the async path.
2. **LRU hot-cache fast-path** — Suricata-style "remember the last
   flow" optimization for monoflow / packet-burst workloads.

## Status

Not started.

## Prerequisites

- Profiling data on representative workloads (perf, tracy,
  flamegraph). Either ad-hoc local profiling or a one-off micro-bench
  set up alongside this plan — whatever gives confidence the
  optimization is targeting a real cost.

## Out of scope

- SIMD acceleration of header parsing (would warrant its own plan).
- Lock-free / shard-by-key flow table (replace HashMap with
  flurry/dashmap). Worth considering only if our profiling points
  to HashMap contention.
- AF_XDP zero-copy frame ownership for flow tracking (separate plan,
  needs aya / xsk-rs evolution first).

---

## Part A — Zero-copy reassembly

### The cost we're paying

Today, `FlowStream::poll_next` for the async-reassembler path does:

```rust
let payload = &view.frame[off..off+len];
let bytes = Bytes::copy_from_slice(payload);  // ALLOC
self.reassembler.pending_payloads.push((..., bytes));
```

`copy_from_slice` allocates a fresh heap `Bytes` per segment. At
1 Gbps with 1500-byte MTU and 50% TCP/data, that's ~80k allocs/sec.
Each costs ~100–300 ns plus heap fragmentation.

### The fix: BytesMut frozen pool

Each batch from the kernel ring is contiguous (well, a block of
contiguous packets). We can:

1. Once per batch, allocate one `BytesMut` of size `batch_len`.
2. Copy the entire batch into it (one big memcpy — fast, prefetcher-
   friendly).
3. For each TCP packet in the batch, `BytesMut::split_to(packet_payload_offset_in_batch)` →
   shareable `Bytes` views.
4. Drop the reassembler's `Bytes` when it consumes them; the underlying
   `BytesMut` ref-count goes to zero when the last reference drops.

End state: 1 alloc per batch (typically 32–256 packets), not per
packet. Throughput gain estimated 1.5–2.5× on TCP-heavy workloads.

### Implementation

In `flow_stream.rs` (the async-reassembler path):

```rust
let batch_total_bytes: usize = batch.iter().map(|p| p.data().len()).sum();
let mut shared = BytesMut::with_capacity(batch_total_bytes);
for pkt in &batch {
    shared.extend_from_slice(pkt.data());
    let frame = &shared[(shared.len() - pkt.data().len())..];
    // ... extractor.extract(view), tracker.track_with_payload(...).
    //     payload_cb takes &[u8] from shared; we materialize Bytes
    //     by splitting:
    //
    //   let payload_offset = shared.len() - pkt.data().len() + tcp.payload_offset;
    //   let payload_bytes = shared.clone().split_to(payload_offset)... 
}
let frozen: Bytes = shared.freeze();
// Hand frozen.slice(off..off+len) to the reassembler — zero-copy.
```

The trick: `Bytes::slice` is O(1) and shares the underlying
allocation. As long as ANY reassembler still holds a slice, the
batch's allocation lives. Once they all drop, it's freed.

### API impact

Internal-only. The user-facing `AsyncReassembler::segment(..., payload: Bytes)`
already takes `Bytes`. We just stop allocating per segment.

### Risks

- **Lifetime extends beyond expected**: if a reassembler holds bytes
  for a long time (e.g., HttpReassembler buffering 1 MB across many
  segments), the underlying batch alloc lives. For pathological
  cases this could push memory up. **Mitigation**: HTTP/TLS/DNS
  parsers should `Bytes::copy_from_slice` themselves when they
  decide to buffer long-term, which converts to an owned alloc.
  Document.

---

## Part B — LRU hot-cache fast-path

### The cost we're paying

Today, every `FlowTracker::track` call does:

```rust
let key = extractor.extract(view).key;
let entry = self.flows.get_mut(&key);  // HashMap lookup
```

For monoflow workloads (e.g., a single iperf3 stream, or a single
HTTP/2 connection saturating a link), every packet is the SAME flow.
The HashMap lookup is ~50 ns; redundant.

Suricata's profiling showed this; their fix is a per-thread "last
flow seen" pointer.

### The fix: sticky reference

Add a thread-local-ish hot cache to `FlowTracker`:

```rust
pub struct FlowTracker<E: FlowExtractor, S = ()> {
    flows: LruCache<...>,
    /// Most recently accessed key — checked first on `track`.
    /// Avoids the HashMap lookup when consecutive packets belong
    /// to the same flow.
    hot: Option<E::Key>,
    // ...
}
```

`track` becomes:

```rust
pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key> {
    let key = extractor.extract(view)?.key;
    if Some(&key) == self.hot.as_ref() {
        // FAST PATH: still touches the LruCache to update LRU order
        // (one O(1) cache.promote()), but skips the bulk lookup.
        // Actually we can skip the LRU promote on `hot` since the
        // hot key is by definition recent.
        let entry = self.flows.get_mut(&key).expect("hot key must exist");
        // ... update entry, return events
    } else {
        // SLOW PATH (existing logic).
        self.hot = Some(key.clone());
        // ... existing track logic
    }
}
```

Estimated win: 2× on monoflow. ~1.05–1.1× on heterogeneous.

### Risks

- **Wrong fast-path on tail of bidirectional flow.** Initiator
  packet then responder packet share the same key in bidirectional
  mode. Confirmed: same key, fast-path wins. ✓
- **Hot-key invalidation on Ended.** When a flow ends and is
  removed from the LruCache, we need to clear `hot` if it points
  there. Add a check in the Ended branch.
- **Code complexity.** Adds ~30 LOC. Trivial.

---

## Files

### MODIFIED

- `netring-flow/src/tracker.rs` — add `hot: Option<E::Key>`
  field + fast-path branch in `track` / `track_with_payload`.
- `netring/src/async_adapters/flow_stream.rs` — switch the async
  reassembler path to the BytesMut-pool pattern.
- `docs/PERFORMANCE.md` — document the new numbers.

---

## Implementation steps

1. **Capture a baseline** with whatever profiler / micro-bench you
   prefer (perf, flamegraph, criterion ad-hoc, hyperfine wrapping
   a flow-replay). Document it inline in PERFORMANCE.md.
2. **Land Part B (hot cache)** first — smaller, simpler change.
3. **Re-measure; document delta.**
4. **Land Part A (BytesMut pool).**
5. **Re-measure; document delta.**
6. **Add `PERFORMANCE.md`** showing before/after for the
   representative workloads (monoflow, 1M-flows, mixed).

---

## Tests

- All existing tests pass after each change.
- Add a property test: feed N packets into the tracker via
  hot-path ON vs OFF (via `cfg!(feature = "no-hot-cache")` fork);
  verify identical event sequences.

---

## Acceptance criteria

- [ ] Hot-cache fast path implemented; measurable throughput gain
      on monoflow workload (target ≥10%).
- [ ] BytesMut pool in async reassembler path; measurable
      throughput gain on TCP-heavy workload (target ≥30%).
- [ ] No regression on existing tests.
- [ ] PERFORMANCE.md has the numbers (before / after / methodology).

---

## Effort

- LOC: ~200 across both parts.
- Time: 3 days (most of it benchmarking + tuning, not coding).
