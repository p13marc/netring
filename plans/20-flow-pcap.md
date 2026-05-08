# Plan 20 — `netring-flow-pcap` companion crate

## Summary

Ship a thin adapter crate that turns pcap files into a stream of
`PacketView`s ready to feed `FlowTracker`. Removes ~10 lines of
boilerplate from every example/program that wants to do flow
tracking on a pcap, and makes the cross-platform claim of
`netring-flow` immediately concrete on macOS/Windows.

## Status

Not started.

## Prerequisites

- Plans 00–04 published as `netring 0.7.0` / `netring-flow 0.1.0`.

## Out of scope

- Pcap *writing* (pcap-file already does this; we don't add value
  by re-wrapping).
- pcapng support beyond what `pcap-file` provides natively.
- Live-capture libpcap binding. That's the `pcap` crate's domain;
  if a user wants both, they pair `netring-flow-pcap` with `pcap`
  via a tiny adapter (documented in the README).

---

## Why this crate

Currently every pcap example does:

```rust
let mut reader = PcapReader::new(BufReader::new(File::open(path)?))?;
while let Some(pkt) = reader.next_packet() {
    let pkt = pkt?;
    let ts = Timestamp::new(pkt.timestamp.as_secs() as u32, pkt.timestamp.subsec_nanos());
    let view = PacketView::new(&pkt.data, ts);
    for evt in tracker.track(view) { ... }
}
```

After this crate:

```rust
let cap = PcapFlowSource::open(path)?;
let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
for view in cap.views() {
    let view = view?;
    for evt in tracker.track(view) { ... }
}
```

Or with a higher-level helper:

```rust
for evt in PcapFlowSource::open(path)?
    .with_extractor(FiveTuple::bidirectional())
{ /* evt is FlowEvent */ }
```

---

## Files

### NEW

```
netring-flow-pcap/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   └── source.rs       # PcapFlowSource + helper iterators
└── examples/
    └── pcap_summary.rs # one-liner using the new crate
```

### MODIFIED

- Workspace `Cargo.toml`: add `netring-flow-pcap` to `members`.
- `plans/INDEX.md`: mark plan 20 in progress / done.

---

## API

```rust
//! netring-flow-pcap — pcap source adapter for netring-flow.

use std::io::{BufReader, Read, Seek};
use std::path::Path;

use netring_flow::{FlowEvent, FlowExtractor, FlowTracker, PacketView, Timestamp};
use pcap_file::pcap::PcapReader;

/// A pcap-backed source of `PacketView`s.
pub struct PcapFlowSource<R: Read> {
    reader: PcapReader<R>,
}

impl PcapFlowSource<BufReader<std::fs::File>> {
    /// Open a pcap file from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error>;
}

impl<R: Read + Seek> PcapFlowSource<R> {
    /// Wrap any `Read + Seek` (e.g., `Cursor<&[u8]>` for tests).
    pub fn from_reader(reader: R) -> Result<Self, Error>;
}

impl<R: Read> PcapFlowSource<R> {
    /// Iterate raw `PacketView`s. Each call yields the next packet
    /// or `Err` on a malformed record.
    pub fn views(self) -> ViewIter<R>;

    /// One-step pipeline: feed every view through `extractor` and
    /// emit `FlowEvent`s. Equivalent to manually constructing a
    /// `FlowTracker` and looping.
    pub fn with_extractor<E: FlowExtractor>(self, extractor: E)
        -> EventIter<R, E, ()>;

    /// Same with explicit per-flow user state.
    pub fn with_extractor_and_state<E, S, F>(
        self,
        extractor: E,
        init: F,
    ) -> EventIter<R, E, S>
    where
        E: FlowExtractor,
        S: Send + 'static,
        F: FnMut(&E::Key) -> S + Send + 'static;
}

/// Iterator yielding `Result<PacketView<'static>, Error>`.
///
/// Note the `'static`: each view owns its data (we copy from the
/// pcap reader because the underlying buffer is reused across
/// `next_packet` calls). This is unavoidable with the pcap-file
/// API; the cost is one alloc per packet, fine for offline analysis.
pub struct ViewIter<R: Read> { /* ... */ }

impl<R: Read> Iterator for ViewIter<R> {
    type Item = Result<OwnedPacketView, Error>;
}

/// An owned `PacketView` — frame bytes in a `Vec<u8>` plus timestamp.
/// Use via `as_view()` to get a borrowed `PacketView<'_>`.
pub struct OwnedPacketView {
    pub frame: Vec<u8>,
    pub timestamp: Timestamp,
}

impl OwnedPacketView {
    pub fn as_view(&self) -> PacketView<'_> {
        PacketView::new(&self.frame, self.timestamp)
    }
}

/// Iterator yielding `Result<FlowEvent<E::Key>, Error>`.
pub struct EventIter<R, E: FlowExtractor, S> {
    /* internal: views + tracker */
}

impl<R, E, S> Iterator for EventIter<R, E, S>
where
    R: Read,
    E: FlowExtractor,
    S: Send + 'static,
{
    type Item = Result<FlowEvent<E::Key>, Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pcap: {0}")]
    Pcap(#[from] pcap_file::PcapError),
}
```

---

## Cargo.toml

```toml
[package]
name = "netring-flow-pcap"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "pcap source adapter for netring-flow flow tracking"
keywords = ["pcap", "flow", "netring"]
categories = ["network-programming"]
readme = "README.md"
documentation = "https://docs.rs/netring-flow-pcap"

[dependencies]
netring-flow = { version = "0.1", path = "../netring-flow", default-features = false, features = ["extractors", "tracker"] }
pcap-file = { workspace = true }
thiserror = { workspace = true }
```

`pcap-file` already exists in `[workspace.dependencies]` — no
workspace deps to add.

---

## Implementation steps

1. **Create the workspace member.**
   - `mkdir -p netring-flow-pcap/src netring-flow-pcap/examples`
   - Write `Cargo.toml` per above.
   - Add `"netring-flow-pcap"` to root `[workspace] members`.
2. **Land `OwnedPacketView`** + `ViewIter`.
   - `next()`: call `reader.next_packet()`, copy `pkt.data` into a
     `Vec<u8>`, build `Timestamp` from `pkt.timestamp`.
   - Yield `Result<OwnedPacketView, Error>`.
3. **Land `PcapFlowSource::open` / `from_reader`.** Wraps the
   `PcapReader::new(BufReader::new(File::open(path)?))?` boilerplate.
4. **Land `EventIter`.**
   - State: an internal `FlowTracker<E, S>` plus a `ViewIter`, and a
     `VecDeque<FlowEvent<E::Key>>` for buffered events.
   - `next()`: drain `pending`, otherwise pull a view, run tracker,
     queue events, repeat.
5. **Final-sweep on iterator end.** When the underlying pcap is
   exhausted, run one `tracker.sweep()` with a far-future timestamp
   to flush remaining flows as `Ended { IdleTimeout }`. Document
   this behavior.
6. **Write `README.md`** with usage example.
7. **Write the example** (`pcap_summary.rs`) — one-liner using
   `with_extractor`.
8. **Test** against the fixtures from Plan 12 (if Plan 12 lands first)
   or against synthetic frames written to a tempfile pcap.
9. **Document the relationship to `netring-flow-tcpdump-style`
   (libpcap)** in the README — explain when to use each.

---

## Tests

### Unit (`netring-flow-pcap/tests/`)

- `view_iter_yields_in_order` — write 3 synthetic packets to a
  tempfile pcap, iterate, assert ordering by timestamp.
- `event_iter_full_lifecycle` — using the `http_session.pcap` fixture
  from Plan 12, assert: 1 Started, 1 Established, 1 Ended (Fin).
- `event_iter_final_sweep_flushes_orphans` — pcap ends mid-flow
  (no FIN); confirm `Ended { IdleTimeout }` is emitted.

### Doctest

```rust
//! ```no_run
//! use netring_flow_pcap::PcapFlowSource;
//! use netring_flow::extract::FiveTuple;
//! use netring_flow::FlowEvent;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! for evt in PcapFlowSource::open("trace.pcap")?.with_extractor(FiveTuple::bidirectional()) {
//!     if let FlowEvent::Started { key, .. } = evt? {
//!         println!("{} <-> {}", key.a, key.b);
//!     }
//! }
//! # Ok(()) }
//! ```
```

---

## Acceptance criteria

- [ ] `cargo build -p netring-flow-pcap` succeeds.
- [ ] `cargo test -p netring-flow-pcap` passes ≥3 tests.
- [ ] `cargo doc -p netring-flow-pcap --no-deps` builds.
- [ ] Example runs: `cargo run -p netring-flow-pcap --example pcap_summary -- tests/data/http_session.pcap`.
- [ ] README cross-references `netring-flow` and explains the
      relationship.
- [ ] Workspace clippy still clean.
- [ ] `cargo publish -p netring-flow-pcap --dry-run` succeeds.

---

## Risks

1. **Per-packet `Vec<u8>` allocation.** Necessary because
   `pcap_file::PcapReader::next_packet` reuses its internal buffer.
   For offline analysis this is fine; if someone asks for zero-copy
   pcap iteration, we'd revisit (probably with a different pcap
   crate or a `BufRead` wrapper).
2. **`pcap-file` pcapng support.** `pcap-file` 2.x supports both
   pcap and pcapng. Check whether `PcapReader` covers both or if we
   need a different entry point. If pcapng requires extra work,
   defer to a v0.2 of this crate.
3. **Crate name reservation.** `netring-flow-pcap` should be
   available on crates.io. Reserve at first publish.
4. **Workspace bloat.** This is the third crate. If it pulls in
   significant deps (pcap-file pulls `byteorder`, `derive-into-owned`,
   nothing too bad). Watch `cargo tree -p netring-flow-pcap`.

---

## Effort

- LOC: ~250 (lib.rs ~50, source.rs ~150, tests ~50).
- Time: 1 day.

---

## What this unlocks

- Direct adoption of `netring-flow` by users with pcap files (which
  is most one-off / forensic / offline analysis).
- Cleaner integration tests in Tier 2 — the HTTP/TLS/DNS bridges
  can use `PcapFlowSource` rather than re-implementing the boilerplate.
- A reference template for how other companion crates should be
  structured.
