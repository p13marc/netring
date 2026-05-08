# Plan 10 — Loopback dedup

## Summary

Land the `Dedup` primitive (combined direction + content-hash filter)
plus the headline async adapter `AsyncCapture::dedup_stream(Dedup)`.
Independent of flow tracking — can ship in any 0.7.x release.

After this plan, capturing on `lo` no longer shows every packet
twice.

## Status

Not started.

## Prerequisites

- [Plan 00](./00-workspace-split.md) (workspace split). Otherwise
  none — independent of plans 01–04.

## Out of scope

- Builder integration on `Capture::builder().dedup(...)`. Defer until
  user demand surfaces.
- Generalized "filter pipeline" framework. Dedup is one concrete
  filter; we don't ship a framework.

---

## Design context

See [`high-level-features-design.md`](./high-level-features-design.md)
Part 1 for the architecture decision (combined direction + content
hash). This plan is the implementation.

---

## Where it lives — `netring` or `netring-flow`?

**Decision: `netring`.**

Why:
- Dedup needs `PacketDirection` (Host/Outgoing) — that's a netring
  type, AF_PACKET-specific.
- Pcap users already get one packet per logical event (no dual
  Outgoing/Host capture). Dedup isn't useful for them.
- The use case is specifically: "I'm capturing on `lo` with netring
  and seeing every packet twice."

If a future user demands generic content-hash dedup divorced from
AF_PACKET, we can extract it then. For 0.7.0, scope it to `netring`.

---

## Files

### NEW (in `netring`)

```
netring/src/
├── dedup.rs                     # Dedup primitive + DedupStats
└── async_adapters/
    └── dedup_stream.rs          # AsyncCapture::dedup_stream + DedupStream
```

### NEW (examples)

- `netring/examples/async_lo_dedup.rs` — capture on `lo`, dedup,
  show stats periodically.

### MODIFIED

- `netring/src/lib.rs` — `pub use dedup::Dedup;`.
- `netring/Cargo.toml` — no new external deps (FNV-1a or xxhash
  rolled inline; ahash already available if we want to share).
- `justfile` — add `lo-dedup` recipe.
- `CHANGELOG.md` — entry under whatever release this lands in.

---

## API

### `netring/src/dedup.rs`

```rust
use std::time::Duration;
use crate::packet::{Packet, PacketDirection};

/// Drop duplicate packets from a capture stream.
///
/// Two configured modes:
///
/// - **Loopback** (`Dedup::loopback()`): tuned for `lo`. Drops the
///   `Host`-direction copy of every `Outgoing` packet seen within
///   1ms. Aggressive but accurate for the kernel's loopback
///   re-injection pattern.
///
/// - **Content** (`Dedup::content(window, ring_size)`): generic
///   content-hash dedup. Drops any packet with the same hash + length
///   as one seen within the configured window. Useful for any
///   capture, but be conservative with the window — long windows
///   suppress legitimate retransmissions.
pub struct Dedup {
    ring: Vec<Entry>,
    head: usize,
    window: Duration,
    direction_aware: bool,
    dropped: u64,
}

#[derive(Clone, Copy)]
struct Entry {
    hash: u64,
    len: u32,
    ts_ns: u64,
    direction: PacketDirection,
}

impl Dedup {
    /// Configured for loopback: 1ms window, 256-entry ring,
    /// direction-aware (Outgoing/Host matching).
    pub fn loopback() -> Self {
        Self::new(Duration::from_millis(1), 256, true)
    }

    /// Generic content dedup with the given window and ring size.
    /// `direction_aware = false`. Use for non-`lo` traffic.
    pub fn content(window: Duration, ring_size: usize) -> Self {
        Self::new(window, ring_size, false)
    }

    /// Custom config — explicit knobs.
    pub fn new(window: Duration, ring_size: usize, direction_aware: bool) -> Self;

    /// Returns true if the packet should be kept.
    /// Updates internal state.
    pub fn keep(&mut self, pkt: &Packet<'_>) -> bool;

    /// Convenience: same logic but operating on (data, direction, ts).
    /// Lets users dedup synthetic frames or frames from non-AF_PACKET
    /// sources where they have constructed PacketDirection themselves.
    pub fn keep_raw(&mut self, data: &[u8], direction: PacketDirection, ts: Timestamp) -> bool;

    pub fn dropped(&self) -> u64 { self.dropped }
}

#[derive(Debug, Clone, Default)]
pub struct DedupStats {
    pub total_seen: u64,
    pub kept: u64,
    pub dropped: u64,
}
```

Hash function: **xxh3-64** via the `xxhash-rust` crate (cheap, no
extra transitive deps, ~200ns for a 1500-byte input). Add to
`netring/Cargo.toml`:

```toml
xxhash-rust = { version = "0.8", default-features = false, features = ["xxh3"] }
```

`xxhash-rust` is ~zero-dep itself. Always-on (no feature flag).

### `netring/src/async_adapters/dedup_stream.rs`

```rust
use std::pin::Pin;
use std::task::{Context, Poll};
use futures_core::Stream;

use crate::AsyncCapture;
use crate::dedup::Dedup;
use crate::packet::OwnedPacket;

pub struct DedupStream {
    cap: AsyncCapture,
    dedup: Dedup,
    pending: std::collections::VecDeque<OwnedPacket>,
}

impl AsyncCapture {
    /// Stream of owned packets with duplicates filtered out.
    pub fn dedup_stream(self, dedup: Dedup) -> DedupStream {
        DedupStream { cap: self, dedup, pending: Default::default() }
    }
}

impl Stream for DedupStream {
    type Item = std::io::Result<OwnedPacket>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(pkt) = this.pending.pop_front() {
            return Poll::Ready(Some(Ok(pkt)));
        }
        loop {
            // Same AsyncFd-driven pattern as flow_stream:
            //   poll_read_ready → try_io → next_batch.
            // For each packet in the batch:
            //   if dedup.keep(&pkt) { pending.push(pkt.to_owned()) }
            // Return the first kept packet, or continue if batch yielded none.
            ...
        }
    }
}
```

The Stream yields `OwnedPacket` (not `Packet<'_>`) because the
batch is consumed inside `poll_next` and we can't borrow across
yields. Users who want zero-copy in dedup land use the manual loop
described in the design doc.

---

## Implementation steps

1. **Land `Dedup` primitive.**
   - `netring/src/dedup.rs` per the API above.
   - Hash: `xxhash-rust::xxh3::xxh3_64(data)`.
   - Ring: `Vec<Entry>` with circular `head` index.
   - `keep`: hash data, scan ring linearly. If match within
     window, drop (return false); else evict oldest, insert new,
     return true.
   - For `direction_aware`: only flag as duplicate if the
     candidate is `Host` and the previous match was `Outgoing` (or
     vice versa). Same direction = legitimate retransmission.
2. **Unit tests.**
   - `Dedup::loopback()` drops Host copy of an Outgoing packet
     seen within 1ms.
   - Same packet seen 2ms later: kept (window expired).
   - Different content, same direction: kept.
   - `Dedup::content(window, 256)` drops same-hash packets within
     window regardless of direction.
3. **Land `DedupStream`.**
   - Stream impl drives `AsyncCapture` via the AsyncFd pattern.
   - On batch: drain, dedup, push kept packets to `pending`.
   - Yield from `pending` one at a time.
4. **Integration test on `lo`.**
   - In `netring/tests/dedup_lo.rs` (gated by
     `integration-tests`):
     - Open AsyncCapture on `lo` with a `Dedup::loopback()`.
     - Spawn a task that does `ping -c 5 127.0.0.1` (or sends UDP
       to 127.0.0.1).
     - Collect `DedupStream` events for 2s.
     - Assert: ≥5 events, ≤10 (without dedup we'd see ~20).
5. **Example.**
   - `netring/examples/async_lo_dedup.rs`:
     ```rust
     // Open lo, dedup_stream(Dedup::loopback()),
     // every second print stats: kept / dropped / drop ratio.
     ```
6. **Justfile recipe.**
   - `lo-dedup *args:` `cargo run -p netring --example async_lo_dedup --features tokio -- {{args}}`
7. **CHANGELOG entry.**
   - Same release as flow (0.7.0) ⇒ add to the consolidated
     0.7.0 section. Otherwise its own 0.7.x point release.
8. **Documentation note.**
   - In `netring/README.md`: short paragraph + link to
     `examples/async_lo_dedup.rs`.
   - If FLOW_GUIDE.md exists (post plan 04), cross-reference dedup
     under "Other utilities" or similar.

---

## Tests

### Unit (`netring/src/dedup.rs`)

- Direction-aware case: 4 packets — 1: A→B Outgoing, 2: A→B Host
  (within 1ms) → drop, 3: A→B Outgoing later (>1ms) → keep, 4:
  A→B Host (within 1ms of 3) → drop.
- Content-only case: 3 same-hash packets within window → 1 kept, 2
  dropped.
- Ring overflow: insert 300 distinct packets into a 256-entry ring,
  verify oldest were evicted.
- `keep_raw` works for synthetic-frame use.
- Counter: `dropped()` increments correctly.

### Integration (`netring/tests/dedup_lo.rs`)

- Real `lo` capture with `Dedup::loopback()`. Sends 5 ICMP echoes
  (via `ping` or raw socket); expects 10 packets pre-dedup, ≤6
  post-dedup (5 echo requests + 5 replies, each seen once).

### Doctest

In `netring/src/dedup.rs`:

```rust
/// ```no_run
/// use netring::{AsyncCapture, Dedup};
/// use futures::StreamExt;
///
/// # async fn example() -> std::io::Result<()> {
/// let cap = AsyncCapture::open("lo")?;
/// let mut stream = cap.dedup_stream(Dedup::loopback());
/// while let Some(pkt) = stream.next().await {
///     let _pkt = pkt?;
///     # break;
/// }
/// # Ok(())
/// # }
/// ```
```

---

## Acceptance criteria

- [ ] `Dedup` compiles, ≥6 unit tests pass.
- [ ] `xxhash-rust` added as a netring dep (no other new deps).
- [ ] `AsyncCapture::dedup_stream` available; doctest builds.
- [ ] `DedupStream` is `Stream<Item = io::Result<OwnedPacket>>`.
- [ ] Integration test on `lo` passes.
- [ ] Example runs and visibly drops ~50% of `lo` traffic.
- [ ] Workspace clippy clean.
- [ ] CHANGELOG entry added.

---

## Risks

1. **`OwnedPacket` allocation cost.** Every kept packet costs one
   `to_owned()` (heap allocation for the data Vec). For high-rate
   `lo` capture (>100k pps), this is the dominant cost. Document;
   provide manual-loop alternative in docs for users who want
   zero-copy.
2. **Hash collisions causing false dedup.** `xxh3-64` collision rate
   is ~1 per 4 billion. For a flow with 1 Mpps × 1ms window = 1000
   packets in window, collision probability per packet is
   ~2.5×10⁻⁷. Real-world: irrelevant. Document anyway.
3. **`direction_aware` isn't always right.** Some kernel setups may
   present packets as `Host`/`Outgoing` in a different order. Test
   on at least 2 distinct kernels (recent stable + 5.x LTS) before
   release.
4. **Ring size 256 might be too small** for high-burst
   loopback traffic — if 256 packets arrive in <1ms the oldest
   slots are reused before their twins arrive. Default size and
   window are tunable via `Dedup::new`. Bench under
   `iperf3 -c 127.0.0.1` and tune if necessary.
5. **Fragmented packets** look identical at the data layer but are
   not really duplicates. The fragment flag in IP header is part of
   the hash input (via xxh3 over full data slice), so this works
   correctly — fragmented vs un-fragmented same-payload differ.
6. **`Capture::builder().dedup(...)`** — the alternative API
   surface from the design doc. Skipped for v1; revisit if users
   ask.

---

## Effort

- LOC: ~250.
  - `dedup.rs`: ~150
  - `dedup_stream.rs`: ~80
  - example + tests: ~150 + ~50
- Time: 1 day.

---

## Sequencing relative to flow plans

This plan is independent of plans 01–04.

- **Option A — ship in 0.7.0 alongside flow**: do this plan after
  plan 02 (so we can demo flow + dedup composing on `lo`) but
  before plan 04 (the release).
- **Option B — ship in 0.6.x ahead of flow**: do this plan
  immediately after plan 00 (workspace split), tag a
  `netring 0.6.1` (no `netring-flow` involved), ship dedup users.
  Then continue with flow plans toward 0.7.0.

**Default**: Option A. The split has fewer release coordination
moments (one publish, one CHANGELOG narrative). Switch to Option B
if there's a user pinging us about loopback dupes who'd benefit
from a faster-than-flow-stack release.
