# Phase 6 — Feature gaps

Net-new public surface area. None of these are bugs; all are gaps that users have
to work around today. Bundle into themed PRs (e.g., "expand `OwnedPacket`",
"add PCAP export").

---

## Fix #27 — Expand `OwnedPacket` to preserve metadata

### Problem

`Packet::to_owned()` (`src/packet.rs:254-260`) discards everything except `data`,
`timestamp`, `original_len`. Lost: `direction`, `vlan_tci`, `vlan_tpid`, `rxhash`,
`status`, `ll_protocol`, `source_ll_addr`. For DPI, flow tracking, or PCAPNG
output (Fix #29), users need at least a subset.

### Plan

**Files:** `src/packet.rs`

Two paths — pick one:

### Option A: extend `OwnedPacket` (simplest, mildly breaking)

```rust
#[derive(Debug, Clone)]
pub struct OwnedPacket {
    pub data: Vec<u8>,
    pub timestamp: Timestamp,
    pub original_len: usize,
    pub status: PacketStatus,
    pub direction: PacketDirection,
    pub rxhash: u32,
    pub vlan_tci: u16,
    pub vlan_tpid: u16,
    pub ll_protocol: u16,
    pub source_ll_addr: heapless::Vec<u8, 8>,  // or smallvec, or Box<[u8]>
}
```

- Most natural for users: one struct, all fields.
- Breaking only if downstream code names fields positionally — but they're all
  named, so this is purely additive.
- Increases `OwnedPacket` size from ~32 to ~80 bytes. For high-pps owned-mode
  capture, this is a real cost.

### Option B: separate `OwnedPacketWithMeta`

```rust
pub struct OwnedPacketWithMeta {
    pub packet: OwnedPacket,
    pub status: PacketStatus,
    pub direction: PacketDirection,
    pub rxhash: u32,
    pub vlan_tci: u16,
    pub vlan_tpid: u16,
    pub ll_protocol: u16,
    pub source_ll_addr: [u8; 8],
    pub source_ll_addr_len: u8,
}

impl Packet<'_> {
    pub fn to_owned_with_meta(&self) -> OwnedPacketWithMeta { ... }
}
```

- Zero-cost for current users.
- Two types, one for each use case.

**Recommendation:** Option A. Fewer types, additive change, modest size growth.
For perf-critical TX-via-channel users we can add `to_minimal_owned()` later if
benchmarks show it matters.

### Tests

Unit:
```rust
#[test]
fn to_owned_preserves_metadata() {
    let block = build_synthetic_block_with_full_meta(...);
    let pkt = iter.next().unwrap();
    let owned = pkt.to_owned();
    assert_eq!(owned.direction, PacketDirection::Outgoing);
    assert_eq!(owned.rxhash, 0xDEADBEEF);
    // ...
}
```

Need to extend `build_synthetic_block` test helper (`src/packet.rs:623`) to
populate the `sockaddr_ll` and `tpacket_hdr_variant1` fields.

### Migration

Adds fields; non-breaking for users who construct `OwnedPacket` literally only if
they use field-init shorthand or struct update syntax. Mark as soft-breaking in
CHANGELOG anyway.

### Checklist
- [ ] Add fields to `OwnedPacket`
- [ ] Update `Packet::to_owned`
- [ ] Update `OwnedPacket::parse` (no change needed if `data` field unchanged)
- [ ] Extend synthetic block builder
- [ ] Unit test
- [ ] Update `tokio_adapter::recv` and `channel.rs` (call sites of `to_owned`)
- [ ] CHANGELOG entry under "Changed"

---

## Fix #28 — Deadline-bounded `Capture::packets`

### Problem

`PacketIter` blocks indefinitely on idle interfaces. CLAUDE.md acknowledges users
must drop down to `next_batch_blocking()` for timeouts. Add a high-level deadline
variant.

### Plan

**Files:** `src/capture.rs`

```rust
impl Capture {
    /// Iterator that stops after `deadline`.
    ///
    /// Like [`packets()`](Self::packets) but each `next()` call respects the
    /// deadline; if the deadline elapses with no packet, the iterator yields
    /// `None` and subsequent calls also return `None`.
    pub fn packets_until(&mut self, deadline: Instant) -> PacketIterDeadline<'_> {
        PacketIterDeadline {
            inner: self.packets_inner(),
            deadline,
        }
    }

    /// Iterator that stops after `total_timeout` from now.
    pub fn packets_for(&mut self, total_timeout: Duration) -> PacketIterDeadline<'_> {
        self.packets_until(Instant::now() + total_timeout)
    }
}

pub struct PacketIterDeadline<'cap> { /* same as PacketIter + deadline */ }

impl<'cap> Iterator for PacketIterDeadline<'cap> {
    type Item = Packet<'cap>;
    fn next(&mut self) -> Option<Packet<'cap>> {
        if Instant::now() >= self.deadline {
            return None;
        }
        let remaining = self.deadline.duration_since(Instant::now());
        // Use min(self.timeout, remaining) for the inner poll.
        ...
    }
}
```

Implementation note: the inner iterator currently uses
`rx.next_batch_blocking(self.timeout)` with a fixed timeout. For
`packets_until` we want to clamp by `min(self.timeout, deadline - now)`. That
requires either:
- Refactoring `PacketIter` to accept a timeout-supplier closure, or
- Duplicating the loop body in `PacketIterDeadline`.

Prefer the closure approach to keep one source of walking logic.

### Tests

Unit:
```rust
#[test]
fn packets_for_returns_none_after_timeout() {
    // Use a synthetic-block-injecting Capture mock — needs the next_batch test hook.
    // Or rely on integration with `lo`:
}
```

Integration (`tests/timeout.rs`):
- `packets_for_terminates_on_idle_iface` — open `Capture` on a quiet veth, call
  `packets_for(Duration::from_millis(200)).count()`, assert it returns within
  300 ms.

### Checklist
- [ ] `Capture::packets_until`
- [ ] `Capture::packets_for`
- [ ] `PacketIterDeadline` type
- [ ] Refactor inner walk to take timeout supplier (or duplicate logic)
- [ ] Integration test
- [ ] Doc/example
- [ ] CHANGELOG entry under "Added"

---

## Fix #29 — PCAP / PCAPNG export feature

### Problem

Common need; users have to wire it up themselves. The crate already supports
optional integrations (`parse` for etherparse), so adding a PCAP feature is
on-pattern.

### Plan

**Cargo.toml:**

```toml
[features]
pcap-write = ["dep:pcap-file"]

[dependencies]
pcap-file = { version = "2", optional = true }
```

`pcap-file` is a pure-Rust PCAP/PCAPNG reader/writer; no native dependency.

**New file:** `src/pcap.rs`

```rust
//! PCAP/PCAPNG export helpers (feature: `pcap-write`).

use std::io::Write;
use crate::packet::{OwnedPacket, Packet};
use pcap_file::pcap::{PcapPacket, PcapWriter};

/// Wraps a [`PcapWriter`] for streaming captures to disk.
pub struct CaptureWriter<W: Write> {
    inner: PcapWriter<W>,
}

impl<W: Write> CaptureWriter<W> {
    pub fn new(writer: W) -> Result<Self, pcap_file::PcapError> {
        Ok(Self { inner: PcapWriter::new(writer)? })
    }

    pub fn write(&mut self, pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError> {
        let pcap_pkt = PcapPacket::new(
            std::time::Duration::new(pkt.timestamp().sec as u64, pkt.timestamp().nsec),
            pkt.original_len() as u32,
            pkt.data(),
        );
        self.inner.write_packet(&pcap_pkt)
    }

    pub fn write_owned(&mut self, pkt: &OwnedPacket) -> Result<(), pcap_file::PcapError> { ... }

    pub fn write_batch(&mut self, batch: &PacketBatch<'_>) -> Result<usize, pcap_file::PcapError> { ... }
}
```

PCAPNG variant analogous (`PcapNgWriter`).

**Examples:**

```rust
// examples/pcap_write.rs
use netring::{Capture, pcap::CaptureWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let path = std::env::args().nth(2).unwrap_or_else(|| "out.pcap".into());

    let mut cap = Capture::new(&iface)?;
    let file = std::fs::File::create(&path)?;
    let mut writer = CaptureWriter::new(file)?;

    for pkt in cap.packets().take(1000) {
        writer.write(&pkt)?;
    }
    Ok(())
}
```

### Tests

Unit (no priv): write a synthetic packet to an in-memory `Cursor<Vec<u8>>`,
read back with `pcap_file::pcap::PcapReader`, assert payload matches.

### Checklist
- [ ] `pcap-file` optional dependency
- [ ] `pcap-write` feature
- [ ] `src/pcap.rs` with `CaptureWriter`
- [ ] PCAPNG variant
- [ ] `examples/pcap_write.rs`
- [ ] Round-trip unit test
- [ ] CHANGELOG entry under "Added"

---

## Fix #30 — TX completion observability

### Problem

`AfPacketTx` has no `wait_completions()` or `pending()`. After `flush`, users
can't ask "is the kernel done with my frames?" without trial-allocations.

### Plan

**Files:** `src/afpacket/tx.rs`

Builds on the slot-status helpers from Fix #9.

```rust
impl AfPacketTx {
    /// Number of slots currently in `TP_STATUS_SEND_REQUEST` or `TP_STATUS_SENDING`.
    pub fn pending_count(&self) -> usize {
        (0..self.frame_count)
            .filter(|&i| {
                let s = self.read_frame_status(i);
                s == ffi::TP_STATUS_SEND_REQUEST || s == ffi::TP_STATUS_SENDING
            })
            .count()
    }

    /// Block until all slots are AVAILABLE or `timeout` elapses.
    ///
    /// Returns `Ok(())` if drained, `Err(Error::Io(TimedOut))` if not.
    pub fn wait_drained(&mut self, timeout: Duration) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        // poll(POLLOUT) on the socket means "TX ring has space"; we want zero pending.
        loop {
            if self.pending_count() == 0 { return Ok(()); }
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(d) => d,
                None => return Err(Error::Io(io::Error::from(io::ErrorKind::TimedOut))),
            };
            // Use poll(POLLOUT) with a short timeout; on wake, re-check.
            let mut pfd = nix::poll::PollFd::new(self.fd.as_fd(), nix::poll::PollFlags::POLLOUT);
            let pt_ms = remaining.min(Duration::from_millis(10));
            let pt = nix::poll::PollTimeout::try_from(pt_ms).unwrap_or(nix::poll::PollTimeout::MAX);
            match nix::poll::poll(&mut [pfd], pt) {
                Ok(_) => continue,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(Error::Io(e.into())),
            }
        }
    }
}
```

Note: `pending_count` is O(frame_count). For large rings (10k+ frames) this can
be costly. Acceptable for diagnostic / shutdown use but document accordingly.

### Tests

Integration (`tests/inject.rs`):
- After 100 frames + flush, `wait_drained(Duration::from_secs(1))` returns Ok.
- Build TX with `frame_count=4`, queue 4 frames without flushing, assert
  `pending_count() == 4`.

### Checklist
- [ ] `AfPacketTx::pending_count`
- [ ] `AfPacketTx::wait_drained`
- [ ] Integration tests
- [ ] CHANGELOG entry under "Added"

---

## Fix #36 — Expose `SO_REUSEPORT`

### Problem

Useful for cooperating with other AF_PACKET listeners on the same iface (e.g.,
when fanout group sharing isn't the right primitive).

### Plan

**Files:** `src/afpacket/socket.rs`, `src/afpacket/rx.rs`, `src/capture.rs`

```rust
// socket.rs
pub(crate) fn set_reuseport(fd: BorrowedFd<'_>, enable: bool) -> Result<(), Error> {
    let val: c_int = if enable { 1 } else { 0 };
    raw_setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &val, "SO_REUSEPORT")
}

// AfPacketRxBuilder + CaptureBuilder
pub fn reuseport(mut self, enable: bool) -> Self { self.reuseport = enable; self }
```

Apply before `bind`.

### Tests

Integration: open two `Capture` instances with `reuseport(true)` on the same iface,
both build successfully. Without SO_REUSEPORT, the second bind fails with EADDRINUSE
on some setups (actually AF_PACKET doesn't enforce single-binding; the SO_REUSEPORT
is more relevant when combined with explicit port binding via TPACKET TX). Add the
setter even if its observable effect is subtle.

### Checklist
- [ ] `set_reuseport` helper
- [ ] Builder methods on `AfPacketRxBuilder`, `CaptureBuilder`, `AfPacketTxBuilder`
- [ ] Unit test (builder propagation)
- [ ] CHANGELOG entry under "Added"

---

## Fix #37 — Expose `SO_RCVBUF`

### Problem

Kernel docs commonly recommend `net.core.rmem_max` tuning + `SO_RCVBUF`. Not a
netring builder option.

### Plan

**Files:** `src/afpacket/socket.rs`, `src/afpacket/rx.rs`, `src/capture.rs`

```rust
// socket.rs
pub(crate) fn set_rcvbuf(fd: BorrowedFd<'_>, bytes: usize) -> Result<(), Error> {
    let val: c_int = bytes.min(c_int::MAX as usize) as c_int;
    raw_setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &val, "SO_RCVBUF")
}

pub(crate) fn set_rcvbufforce(fd: BorrowedFd<'_>, bytes: usize) -> Result<(), Error> {
    let val: c_int = bytes.min(c_int::MAX as usize) as c_int;
    raw_setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &val, "SO_RCVBUFFORCE")
}
```

Builder: `pub fn rcvbuf(mut self, bytes: usize) -> Self`. If `force`, try
`SO_RCVBUFFORCE` first (requires CAP_NET_ADMIN), fall back to `SO_RCVBUF`.

### Tests

Unit propagation; integration assertions are tricky because the kernel doubles
the value silently. Skip integration assertion.

### Checklist
- [ ] `set_rcvbuf` + `set_rcvbufforce`
- [ ] Builder methods
- [ ] Doc note about kernel doubling and `net.core.rmem_max`
- [ ] CHANGELOG entry under "Added"

---

## Fix #38 — Doc-string accuracy & cleanup

### Problem

A grab-bag of small inconsistencies:

1. README links to `docs/AF_XDP_EVALUATION.md` but the file isn't referenced from
   library rustdoc.
2. `tokio_adapter::AsyncCapture::recv` doc shows `cap.recv().await?` but doesn't
   mention spurious-wakeup re-arming inside the loop.
3. `interface.rs:54` reads `device/driver` symlink; `unwrap_or_default()` swallows
   real I/O errors silently.
4. Mismatched terms: "block" vs "batch" used interchangeably in some docstrings.

### Plan

**Files:** various

1. **README cross-links** — add a section in `lib.rs` rustdoc pointing to
   `docs/ARCHITECTURE.md` and the AF_XDP evaluation when the `af-xdp` feature is
   enabled.

2. **`AsyncCapture::recv` docstring** — explicitly note:

   ```rust
   /// Internally loops until a non-empty batch arrives or an I/O error occurs.
   /// Spurious wakeups are absorbed (the inner `next_batch()` may return `None`
   /// even after readability fires; we re-arm and re-wait).
   ```

3. **`interface_info` error visibility** — replace silent `unwrap_or_default()`
   with `tracing::debug!`-level logging:

   ```rust
   let driver = read_sysfs_link_basename(name, "device/driver")
       .map_err(|e| { tracing::debug!(iface = name, error = %e, "no driver info"); e })
       .unwrap_or_default();
   ```

4. **Glossary** — append a "Terminology" section to `docs/ARCHITECTURE.md`:

   - **Block**: kernel-level unit of TPACKET_V3 ring storage.
   - **Batch**: user-facing wrapper around one block (`PacketBatch`).
   - **Frame**: TX-side fixed-size slot.
   - **Packet**: payload + metadata at the user's level.

   Audit all rustdoc to ensure these terms are used consistently.

### Tests

None — docs only.

### Checklist
- [ ] README/lib.rs cross-link
- [ ] `AsyncCapture::recv` doc
- [ ] `interface_info` log statements
- [ ] Glossary section
- [ ] Term audit pass
- [ ] CHANGELOG entry under "Changed (docs)"

---

## Fix #44 — `AsyncCapture::try_recv_batch`

### Problem

Currently the only path is `wait_readable() + get_mut().next_batch()` (two calls).
A combined `try_recv_batch().await -> Option<PacketBatch<'_>>` would be friendlier.

### Plan

**Files:** `src/async_adapters/tokio_adapter.rs`

Implemented as part of Fix #25's `ReadableGuard::next_batch`. The guard holds
`&mut self` and yields the batch lifetime-tied to the guard. Document this as the
canonical entry point.

```rust
// Combined helper (sugar over `readable().await?.next_batch()`):
impl<S: PacketSource + AsRawFd> AsyncCapture<S> {
    /// Wait for readability and return the next batch in one call.
    ///
    /// Equivalent to `self.readable().await?.next_batch()` plus a loop on
    /// spurious wakeups. Returns `Ok(None)` only on errors that warrant
    /// `take_error()`-style inspection (currently never).
    pub async fn try_recv_batch(&mut self) -> Result<PacketBatch<'_>, Error> {
        loop {
            let mut guard = self.inner.readable_mut().await.map_err(Error::Io)?;
            // SAFETY: lifetime erasure same as PacketIter; the batch is tied
            // to &mut self via the guard.
            if let Some(batch) = guard.get_inner_mut().next_batch() {
                return Ok(unsafe { std::mem::transmute(batch) });
            }
            guard.clear_ready();
        }
    }
}
```

### Tests

Doctest pattern; integration covered by existing async tests.

### Checklist
- [ ] `try_recv_batch` method
- [ ] Doctest
- [ ] CHANGELOG entry under "Added"

---

## Fix #45 — Optional Prometheus / metrics integration

### Problem

Common for production capture — users wire up Prometheus counters by hand against
`stats()`. A first-class adapter would eliminate boilerplate.

### Plan

**Cargo.toml:**

```toml
[features]
metrics = ["dep:metrics"]

[dependencies]
metrics = { version = "0.24", optional = true }
```

The `metrics` crate is the de-facto standard façade. Users pick a backend
(prometheus, statsd, etc.).

**New file:** `src/metrics.rs`

```rust
//! Optional metrics integration (feature: `metrics`).
//!
//! Exports `netring_*` metrics via the `metrics` crate façade.

use crate::stats::CaptureStats;

/// Records `netring_capture_packets_total`, `netring_capture_drops_total`,
/// `netring_capture_freezes_total` counters from a `CaptureStats` delta.
pub fn record_capture_delta(iface: &str, delta: &CaptureStats) {
    metrics::counter!("netring_capture_packets_total", "iface" => iface.to_string())
        .increment(delta.packets as u64);
    metrics::counter!("netring_capture_drops_total", "iface" => iface.to_string())
        .increment(delta.drops as u64);
    metrics::counter!("netring_capture_freezes_total", "iface" => iface.to_string())
        .increment(delta.freeze_count as u64);
}
```

Optional: a wrapper struct that polls stats on a timer and records automatically.
Defer to user-space.

### Tests

Unit: with a test `metrics` recorder, call `record_capture_delta` and assert
counters incremented.

### Checklist
- [ ] `metrics` optional dependency
- [ ] `metrics` feature
- [ ] `src/metrics.rs` with helper
- [ ] Unit test using `metrics`'s test recorder
- [ ] CHANGELOG entry under "Added"
