# Plan 50 — Deferred-feature catchup

## Summary

Six small features deferred from earlier plans, packaged as one
deliverable so we don't end up with a flurry of micro-versions.
Each is small (10–80 LOC); together ~250 LOC and 2 days of work.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- Some items (notably async state init) benefit from waiting for
  user feedback on the existing API.

## Items

| Sub-plan | What | Effort |
|----------|------|--------|
| 50.1 | `InnerGre<E>` — strip GRE encapsulation | 50 LOC |
| 50.2 | `FlowLabel<E>` — IPv6 flow label augmentation | 80 LOC |
| 50.3 | `AutoDetectEncap<E>` — combinator that walks any common encap | 100 LOC |
| 50.4 | `FlowTracker::manual_tick(now)` — explicit sweep for tests | 20 LOC |
| 50.5 | IPv6 fragment reassembly via `IpFragReassembler` adapter | 200 LOC + tests |
| 50.6 | `FlowStream::broadcast(buffer)` — multi-subscriber helper | 80 LOC |

(Total above is ~530 LOC; some of it is tests. Code-only: ~350 LOC.)

---

## 50.1 — `InnerGre<E>`

GRE (Generic Routing Encapsulation, RFC 2784) encapsulates L3
inside IP protocol 47. Header is 4 bytes minimum: 2 bytes flags +
2 bytes protocol type. Optional extensions for checksum, key,
sequence, all conditional on flag bits.

### API

```rust
pub struct InnerGre<E> {
    pub extractor: E,
}

impl<E: FlowExtractor> FlowExtractor for InnerGre<E> {
    type Key = E::Key;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let inner = peel_gre(view.frame)?;
        // inner is bare IP — synthesize Ethernet, delegate
        let synth = synthesize_eth_for_ip(inner)?;
        self.extractor.extract(view.with_frame(&synth))
    }
}
```

### Tests

- Synthetic IPv4-in-GRE
- Synthetic IPv6-in-GRE
- GRE with checksum extension
- GRE with key extension
- Wrong protocol number (should return None)

---

## 50.2 — `FlowLabel<E>`

IPv6 flow label is 20 bits in the IPv6 header. Some traffic uses it
to distinguish flows that would otherwise share a 5-tuple (e.g.,
ECMP hash inputs). Provides a 20-bit augmentation to the flow key.

### API

```rust
pub struct FlowLabel<E> {
    pub extractor: E,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FlowLabelKey<K> {
    pub inner: K,
    pub label: u32,  // 20-bit, in low bits
}

impl<E: FlowExtractor> FlowExtractor for FlowLabel<E>
where
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    type Key = FlowLabelKey<E::Key>;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<FlowLabelKey<E::Key>>>;
}
```

If the inner is IPv4 (no flow label), `label = 0`. Document.

---

## 50.3 — `AutoDetectEncap<E>`

For users with mixed traffic (some plain, some VLAN, some VXLAN),
a single combinator that tries decap variants in order and picks
the first one that succeeds.

### API

```rust
pub struct AutoDetectEncap<E> {
    pub extractor: E,
    pub variants: AutoEncapVariants,
}

#[derive(Debug, Clone)]
pub struct AutoEncapVariants {
    pub vlan: bool,
    pub mpls: bool,
    pub vxlan: bool,
    pub gtp_u: bool,
    pub gre: bool,
}

impl AutoEncapVariants {
    pub fn all() -> Self;
}

impl<E: FlowExtractor + Clone> FlowExtractor for AutoDetectEncap<E> {
    type Key = E::Key;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        // Try plain first; then each enabled variant in order.
        if let Some(e) = self.extractor.extract(view) { return Some(e); }
        if self.variants.vlan {
            if let Some(e) = StripVlan(self.extractor.clone()).extract(view) { return Some(e); }
        }
        if self.variants.vxlan {
            if let Some(e) = InnerVxlan::new(self.extractor.clone()).extract(view) { return Some(e); }
        }
        // ... etc
        None
    }
}
```

**Cost**: up to 5× the hot-path cost of a single extractor for
unmatched packets. Document. For users who know their traffic
shape, manual composition (`StripVlan(InnerVxlan(...))`) is faster.

---

## 50.4 — `FlowTracker::manual_tick(now)`

For tests that want deterministic sweep behavior:

```rust
impl<E: FlowExtractor, S> FlowTracker<E, S> {
    /// Run a sweep at `now`. Same as `sweep`, but exists for
    /// API symmetry — `sweep` will likely be the documented
    /// name; this is the alias for users who prefer it.
    pub fn manual_tick(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        self.sweep(now)
    }
}
```

Trivial — but the alias exists for tests + docs that want a name
that doesn't sound like background-thread machinery.

---

## 50.5 — IPv6 fragment reassembly

Currently `etherparse` parses the first fragment but doesn't
reassemble. Most flow tracking can ignore fragments (they contribute
to byte counts via the first fragment), but for correctness on
heavily-fragmented workloads users want the inner header.

### API

```rust
/// Reassembles IPv4/IPv6 fragments before extraction.
pub struct ReassembledFragments<E> {
    pub extractor: E,
    pub buffer_max_bytes: usize,        // default: 1 MiB
    pub timeout: Duration,               // default: 60s (RFC 8200 §4.5)
    state: Arc<Mutex<FragState>>,
}

impl<E: FlowExtractor> FlowExtractor for ReassembledFragments<E> {
    type Key = E::Key;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        // Detect fragment, accumulate, emit only when reassembled.
        // For first fragments, emit immediately AND track for the rest.
    }
}
```

### Risks

- **Reassembly attacks** (fragmentation overlap, tiny fragments) —
  follow RFC 8200 / RFC 5722 strict rules.
- **Memory** — bounded by `buffer_max_bytes` per source IP pair.
- **Cross-thread state** — `Arc<Mutex<FragState>>` gates parallel
  use. Document.

---

## 50.6 — `FlowStream::broadcast(buffer)`

Sometimes users want multiple consumers seeing the same flow events
(e.g., a logger + a metrics exporter + a real-time UI). Today,
`flow_stream` consumes the capture; you can only have one subscriber.

### API

```rust
impl<S, E, U, R> FlowStream<S, E, U, R>
where E::Key: Clone + Send + Sync + 'static
{
    /// Convert into a broadcast-style stream where multiple
    /// subscribers can receive the same events.
    ///
    /// `buffer` is the per-subscriber lag tolerance — a slow
    /// subscriber missing this many events gets a `Lagged` error.
    pub fn broadcast(self, buffer: usize) -> FlowBroadcast<E::Key>;
}

pub struct FlowBroadcast<K> {
    sender: tokio::sync::broadcast::Sender<Arc<FlowEvent<K>>>,
    /// Background task driving the underlying FlowStream.
    _task: tokio::task::JoinHandle<()>,
}

impl<K: Clone + Send + 'static> FlowBroadcast<K> {
    pub fn subscribe(&self) -> impl Stream<Item = Result<Arc<FlowEvent<K>>, BroadcastError>>;
}
```

Wraps `tokio::sync::broadcast::channel(buffer)`. Each `subscribe()`
returns a fresh stream. Slow subscribers see `Lagged` errors but
don't block others.

`Arc<FlowEvent<K>>` so we don't clone the (potentially large)
event for every subscriber.

---

## Files

### MODIFIED / NEW

```
netring-flow/src/extract/encap_gre.rs          # NEW
netring-flow/src/extract/flow_label.rs         # NEW
netring-flow/src/extract/auto_detect.rs        # NEW
netring-flow/src/extract/frag_reassembler.rs   # NEW (or stub for v1)
netring-flow/src/extract/mod.rs                # update re-exports
netring-flow/src/tracker.rs                    # add manual_tick
netring/src/async_adapters/flow_broadcast.rs   # NEW
netring/src/async_adapters/mod.rs              # wire
```

---

## Implementation steps

1. **50.4 first** (trivial; alias).
2. **50.1, 50.2, 50.3** (parser additions; tests against synthetic
   frames).
3. **50.6** (broadcast helper).
4. **50.5** (fragment reassembly — most complex; could split into
   its own micro-plan if it grows).

---

## Acceptance criteria

- [ ] All 6 features ship under one tag.
- [ ] Each has ≥3 unit tests.
- [ ] CHANGELOG entry covers all six.
- [ ] No regressions on existing tests.

## Effort

- LOC: ~530 (incl. tests).
- Time: 2 days.
