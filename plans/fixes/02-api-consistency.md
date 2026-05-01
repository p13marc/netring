# Phase 2 — Silent failures, missing setters, error semantics

These fixes address API surface that exists but is broken, missing, or misleading.
None are breaking; bundle 2-3 per PR for review economy.

---

## Fix #5 — `MmapRing` MAP_LOCKED retry log message accuracy

### Problem

`src/afpacket/ring.rs:51-62` retries `mmap` for `EPERM | ENOMEM | EAGAIN` without
`MAP_LOCKED`, logging:

```
"mmap with MAP_LOCKED failed, retrying without (consider CAP_IPC_LOCK)"
```

EPERM is the only case where `CAP_IPC_LOCK` is the relevant cause. ENOMEM/EAGAIN
suggest `RLIMIT_MEMLOCK` exhaustion or genuine OOM, and the log message is
misleading.

### Plan

**Files:** `src/afpacket/ring.rs`

Replace the matched arms with cause-specific logs:

```rust
let ptr = match result {
    Ok(p) => p,
    Err(e @ (nix::errno::Errno::EPERM | nix::errno::Errno::ENOMEM | nix::errno::Errno::EAGAIN)) => {
        let hint = match e {
            nix::errno::Errno::EPERM   => "missing CAP_IPC_LOCK",
            nix::errno::Errno::ENOMEM  => "RLIMIT_MEMLOCK exhausted or OOM",
            nix::errno::Errno::EAGAIN  => "RLIMIT_MEMLOCK exhausted",
            _ => unreachable!(),
        };
        tracing::warn!(error = %e, hint, "mmap MAP_LOCKED failed; retrying without MAP_LOCKED");
        let flags_no_lock = MapFlags::MAP_SHARED | MapFlags::MAP_POPULATE;
        unsafe { nix::sys::mman::mmap(None, length, prot, flags_no_lock, &fd, 0) }
            .map_err(|e| Error::Mmap(e.into()))?
    }
    Err(e) => return Err(Error::Mmap(e.into())),
};
```

### Tests

Pure logging — no test required. Mention in the next CHANGELOG entry.

### Checklist
- [ ] Patch the warn path
- [ ] CHANGELOG entry under "Changed"

---

## Fix #6 — EINTR handling for blocking syscalls

### Problem

Long-running captures can receive any signal (SIGCHLD, SIGUSR1 etc.). Today every
blocking syscall propagates `EINTR` as `Error::Io`:

| Site                                  | File                          |
|---------------------------------------|-------------------------------|
| `nix::poll::poll` in `next_batch_blocking` | `src/afpacket/rx.rs:118` |
| `libc::sendto` in `flush`             | `src/afpacket/tx.rs:200`      |
| `libc::poll` in `XdpSocket::poll`     | `src/afxdp/mod.rs:422`        |
| `libc::sendto` in `XdpSocket::flush`  | `src/afxdp/mod.rs:391`        |
| `nix::poll::poll` in `Bridge` (post-#2) | `src/bridge.rs`            |

### Plan

**New file:** `src/syscall.rs`

```rust
//! EINTR-safe wrappers around blocking syscalls used in netring.

use std::time::Duration;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::errno::Errno;

/// Run `nix::poll::poll`, retrying on EINTR.
pub(crate) fn poll_eintr_safe(pfds: &mut [PollFd<'_>], timeout: Duration) -> nix::Result<i32> {
    let pt = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX);
    loop {
        match poll(pfds, pt) {
            Err(Errno::EINTR) => continue,
            other => return other,
        }
    }
}

/// Run `libc::sendto(NULL, 0)` (TPACKET TX kick), retrying on EINTR.
///
/// `flags`: 0 for AF_PACKET, `MSG_DONTWAIT` for AF_XDP.
/// Returns: `Ok(())` on success, `Ok(())` for transient EAGAIN/ENOBUFS, `Err` otherwise.
pub(crate) fn sendto_kick_eintr_safe(fd: std::os::fd::RawFd, flags: i32) -> std::io::Result<()> {
    loop {
        let ret = unsafe {
            libc::sendto(fd, std::ptr::null(), 0, flags, std::ptr::null(), 0)
        };
        if ret >= 0 { return Ok(()); }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) | Some(libc::ENOBUFS) => return Ok(()),
            _ => return Err(err),
        }
    }
}
```

Add `pub(crate) mod syscall;` to `src/lib.rs`.

**Refactor** the existing call sites to use these helpers. Note: `AfPacketTx::flush`
treats EAGAIN as a real failure today; align with `XdpSocket::flush` behavior — both
are non-fatal when the kernel queue is briefly full. Document the change.

### Tests

Direct EINTR is hard to unit-test. Add an integration test gated by a `#[cfg(unix)]`
helper that:

1. Spawns a thread doing `next_batch_blocking(Duration::from_secs(2))` on a quiet
   `lo` capture.
2. Main thread waits 100 ms, sends `SIGUSR1` to the worker via `pthread_kill`.
3. Asserts `next_batch_blocking` returns `Ok(None)` after the timeout (not Err).

Place in `tests/eintr.rs` gated `integration-tests`. Skip on platforms without
`pthread_kill` exposure (all Linux fine).

### Checklist
- [ ] `src/syscall.rs` with helpers
- [ ] Refactor `AfPacketRx::next_batch_blocking`
- [ ] Refactor `AfPacketTx::flush`
- [ ] Refactor `XdpSocket::poll`
- [ ] Refactor `XdpSocket::flush`
- [ ] EINTR integration test
- [ ] CHANGELOG entry under "Fixed"

---

## Fix #7 — `fill_rxhash` builder setter

### Problem

`AfPacketRxBuilder` has a private `fill_rxhash: bool` field defaulting to true and
consumed in `build()` (`src/afpacket/rx.rs:337-341`), but no public setter. Users
cannot turn it off.

### Plan

**Files:** `src/afpacket/rx.rs`, `src/capture.rs`

1. `AfPacketRxBuilder`:
   ```rust
   /// Request the kernel to fill `rxhash` on each received packet (RSS/flow hash).
   ///
   /// Default: `true`. Disabling can shave a few % CPU on the kernel side.
   pub fn fill_rxhash(mut self, enable: bool) -> Self {
       self.fill_rxhash = enable;
       self
   }
   ```

2. `CaptureBuilder`: add the same field + setter, and propagate via `make_rx_builder`:
   ```rust
   b = b.fill_rxhash(self.fill_rxhash);
   ```

### Tests

Unit:
```rust
#[test]
fn fill_rxhash_default_is_true() {
    assert!(AfPacketRxBuilder::default().fill_rxhash);
}

#[test]
fn fill_rxhash_setter() {
    let b = AfPacketRxBuilder::default().fill_rxhash(false);
    assert!(!b.fill_rxhash);
}
```

### Checklist
- [ ] `AfPacketRxBuilder::fill_rxhash`
- [ ] `CaptureBuilder::fill_rxhash` + propagation
- [ ] Unit tests
- [ ] Doc note in `docs/TUNING_GUIDE.md`
- [ ] CHANGELOG entry under "Added"

---

## Fix #8 — `FanoutMode::Ebpf` is unusable

### Problem

`src/config.rs:21-26` documents `FanoutMode::Ebpf` as "Requires attaching an eBPF
program fd via `CaptureBuilder::fanout_ebpf()` or `AfPacketRx::attach_ebpf_filter()`".
Neither method exists. The internal `attach_fanout_ebpf` (`src/afpacket/fanout.rs:40`)
is `pub(crate)` and `#[allow(dead_code)]`.

### Plan

**Files:** `src/afpacket/fanout.rs`, `src/afpacket/rx.rs`, `src/capture.rs`,
`src/config.rs`

1. Remove `#[allow(dead_code)]` from `attach_fanout_ebpf`.

2. Add to `AfPacketRx`:

   ```rust
   /// Attach an eBPF program to govern fanout distribution.
   ///
   /// Must be called after [`build()`](AfPacketRxBuilder::build) on a socket whose
   /// builder used `.fanout(FanoutMode::Ebpf, group_id)`. The program type must be
   /// `BPF_PROG_TYPE_SOCKET_FILTER`; it returns the 0-based socket index within
   /// the fanout group.
   ///
   /// # Errors
   /// [`Error::SockOpt`] if `setsockopt(PACKET_FANOUT_DATA)` fails (e.g., the
   /// fanout group was not created with `FanoutMode::Ebpf`).
   pub fn attach_fanout_ebpf<F: AsFd>(&self, prog: F) -> Result<(), Error> {
       crate::afpacket::fanout::attach_fanout_ebpf(self.fd.as_fd(), prog.as_fd())
   }
   ```

   Note: takes `AsFd` not `RawFd` to avoid the issue in Fix #19. Ripple the fanout
   helper signature accordingly.

3. Same method on `Capture` (delegates to the inner `rx`).

4. Optionally allow attaching the program at builder time:

   ```rust
   // CaptureBuilder
   pub fn fanout_ebpf<F: AsFd + 'static>(mut self, prog: F) -> Self {
       self.fanout_ebpf_prog = Some(Box::new(prog) as Box<dyn AsFd>);
       self
   }
   ```

   …then in `build()`, if `self.fanout` is `Some((Ebpf, _))` and `fanout_ebpf_prog`
   is set, call `attach_fanout_ebpf` after the fanout join.

   Skip the builder method if it complicates the type signature too much; the
   post-build `attach_fanout_ebpf` is sufficient.

5. Update the rustdoc on `FanoutMode::Ebpf` to point at the actual method names.

### Tests

Unit: assert the method exists and accepts an `OwnedFd` (smoke test only — real
testing needs an actual eBPF program). Add an example `examples/ebpf_fanout.rs`
that uses `aya` to load a trivial dispatcher.

### Migration

Non-breaking. Doc-fixed, new public methods.

### Checklist
- [ ] Make `attach_fanout_ebpf` reachable (remove dead-code annotations)
- [ ] `AfPacketRx::attach_fanout_ebpf`
- [ ] `Capture::attach_fanout_ebpf`
- [ ] (Optional) builder integration
- [ ] Update `FanoutMode::Ebpf` docs
- [ ] (Optional) `examples/ebpf_fanout.rs`
- [ ] CHANGELOG entry under "Added"

---

## Fix #9 — `AfPacketTx::flush` returns inflated success count

### Problem

`src/afpacket/tx.rs:182-207`: `flush()` returns the count of *queued* frames
unconditionally after `sendto` succeeds. Frames the kernel rejected
(`TP_STATUS_WRONG_FORMAT`) or hasn't yet sent (`TP_STATUS_SENDING`) are not
distinguished, so the user's "X frames flushed" is a queued-not-sent count.

### Plan

**Files:** `src/afpacket/tx.rs`

1. Rename in docstrings only — the return value's semantics become "queued for
   transmission". Update the doc:

   ```rust
   /// Kick the kernel to transmit all frames queued via [`TxSlot::send()`].
   ///
   /// Returns the number of frames that were queued (i.e., had `TP_STATUS_SEND_REQUEST`
   /// set) when this call started. **This is not necessarily the number of frames
   /// transmitted** — the kernel may take additional time to process them, may reject
   /// frames with malformed headers (`TP_STATUS_WRONG_FORMAT`), or may not yet have
   /// reclaimed their slots (`TP_STATUS_SENDING`).
   ///
   /// To distinguish queued-vs-sent, scan slot status after a `flush` via
   /// [`completed_count()`](Self::completed_count) or wait for slot reclamation
   /// before re-using.
   ```

2. Add a status-scanning helper:

   ```rust
   /// Count slots currently in `TP_STATUS_AVAILABLE` (i.e., reclaimed by kernel).
   ///
   /// Useful after `flush` to estimate transmission progress.
   pub fn available_slots(&self) -> usize {
       (0..self.frame_count)
           .filter(|&i| self.read_frame_status(i) == ffi::TP_STATUS_AVAILABLE)
           .count()
   }

   /// Count slots in `TP_STATUS_WRONG_FORMAT`.
   ///
   /// Non-zero values indicate kernel rejected frames — typically a header/length
   /// mismatch or unsupported feature flag.
   pub fn rejected_slots(&self) -> usize {
       (0..self.frame_count)
           .filter(|&i| self.read_frame_status(i) == ffi::TP_STATUS_WRONG_FORMAT)
           .count()
   }
   ```

3. (Optional) add a richer return type behind a feature flag:

   ```rust
   pub struct TxFlushReport {
       pub queued: usize,
       pub rejected_at_call: usize,
   }
   ```

   Only worth it if downstream needs this; defer.

### Tests

Integration `tests/inject.rs`:
- After 100 frames + `flush()`, eventually `available_slots()` reaches 100 (poll
  with timeout).
- Construct an intentionally too-short frame (length 0) and verify
  `rejected_slots() > 0` after flush — this requires bypassing the
  `TxSlot::set_len` assertion. Add a low-level helper or skip this test if it
  requires unsafe.

### Migration

Non-breaking. Adds methods; existing semantics of `flush()` unchanged in code,
just better documented.

### Checklist
- [ ] Update `flush` docstring
- [ ] `available_slots()` accessor
- [ ] `rejected_slots()` accessor
- [ ] Integration test for slot reclamation
- [ ] CHANGELOG entry under "Added" (accessors) and "Fixed" (docs)

---

## Fix #10 — `AfPacketTx::Drop` silently discards flush errors

### Problem

`src/afpacket/tx.rs:226-231`:
```rust
impl Drop for AfPacketTx {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}
```

If the user relied on uncompleted frames going out, they get no signal of failure.

### Plan

**Files:** `src/afpacket/tx.rs`

1. Update doc on `AfPacketTx`:

   ```rust
   /// # Drop semantics
   ///
   /// `Drop` performs a best-effort `flush` to push any pending frames to the
   /// kernel before unmapping the ring. **Errors from this final flush are
   /// discarded** — call [`flush()`](Self::flush) explicitly before dropping if
   /// you need to observe transmission failures.
   ```

2. Log the error (downgrade from "discard" to "discard-with-trace") for debuggability:

   ```rust
   impl Drop for AfPacketTx {
       fn drop(&mut self) {
           if let Err(e) = self.flush() {
               tracing::warn!(error = %e, "AfPacketTx::drop final flush failed");
           }
       }
   }
   ```

### Tests

None — pure docs/log change.

### Checklist
- [ ] Update `Drop` impl
- [ ] Update `AfPacketTx` doc
- [ ] CHANGELOG entry under "Changed"

---

## Fix #11 — Verify `PACKET_QDISC_BYPASS` ordering

### Problem

`src/afpacket/tx.rs:312-330` sets `PACKET_QDISC_BYPASS` after `bind` and after
`PACKET_TX_RING`. Linux man pages and `netsniff-ng` set it before `bind`.

### Plan

**Files:** `src/afpacket/tx.rs`

1. Read kernel source `net/packet/af_packet.c` to verify whether
   `PACKET_QDISC_BYPASS` is honored at any time or must precede `bind`. Likely
   answer: it sets a flag on the `packet_sock` struct, no ordering requirement.

2. If the kernel allows post-bind setting (very likely): leave the code as-is but
   add a comment citing the kernel source line. No behavior change.

3. If kernel requires pre-bind: move the setsockopt to before `bind_to_interface`.

Track in CHANGELOG only if behavior changes.

### Tests

If we move the setsockopt, the existing inject integration tests cover regression.

### Checklist
- [ ] Read kernel source to confirm ordering requirement
- [ ] Either add justifying comment or move the call
- [ ] (If moved) verify integration tests still pass
- [ ] CHANGELOG entry only if behavior changed

---

## Fix #16 — `Bridge::stats()` resets counters

### Problem

`src/bridge.rs:162-167` calls `rx.stats()` for both directions, which resets the
kernel counters. The doc on `Bridge::stats()` does not warn about this; users
expect stats reads to be idempotent.

### Plan

**Files:** `src/bridge.rs`

1. Update doc:

   ```rust
   /// Forwarding statistics for both directions.
   ///
   /// **Reads are destructive**: the underlying `getsockopt(PACKET_STATISTICS)`
   /// resets kernel counters. To accumulate over time, sum results from periodic
   /// calls.
   ```

2. (Optional, paired with Fix #18) consider a `Bridge::accumulated_stats()` that
   maintains internal totals across calls. Defer to phase 6.

### Tests

None — doc-only change.

### Checklist
- [ ] Update `Bridge::stats` docstring
- [ ] Cross-reference Fix #18 in TODO comment

---

## Fix #17 — `PacketIter::next` swallows errors

### Problem

`src/capture.rs:432-433`: `Err(_) => return None`. The iterator silently terminates
on any I/O error — the user has no way to differentiate "ok done" (impossible for a
live capture) from "broken pipe".

### Plan

**Files:** `src/capture.rs`

Implemented as part of Fix #4 — store the error in `last_error` and expose:

```rust
impl<'cap> PacketIter<'cap> {
    /// Take the most recent error that caused the iterator to terminate.
    ///
    /// Returns `None` if the iterator hasn't terminated or terminated cleanly.
    /// Calling consumes the error — subsequent calls return `None`.
    pub fn take_error(&mut self) -> Option<Error> {
        self.last_error.take()
    }
}
```

Update `Capture::packets` rustdoc to document the new pattern:

```rust
/// # Error handling
///
/// `PacketIter` returns `None` on I/O error. Call [`take_error()`](PacketIter::take_error)
/// after iteration to inspect any failure:
///
/// ```no_run
/// # let mut cap = netring::Capture::new("lo").unwrap();
/// let mut iter = cap.packets();
/// for pkt in iter.by_ref() {
///     // process
///     # let _ = pkt;
/// }
/// if let Some(e) = iter.take_error() {
///     eprintln!("capture stopped: {e}");
/// }
/// ```
```

### Tests

Hard to trigger an error mid-iteration in a unit test. Add a `cfg(test)` injection
hook on `AfPacketRx` that returns `Err` on the next `next_batch_blocking` call,
then verify `iter.take_error().is_some()`.

### Checklist
- [ ] `last_error` field on `PacketIter`
- [ ] `take_error()` method
- [ ] Doc update on `Capture::packets`
- [ ] Test (with the injection hook) — bundle with Fix #4 PR

---

## Fix #18 — `Capture::stats(&self)` mutates kernel state

### Problem

`Capture::stats(&self)` and `AfPacketRx::stats(&self)` perform a destructive read of
`PACKET_STATISTICS`. The `&self` signature suggests idempotence; over-eager monitoring
loses counts.

### Plan

**Files:** `src/afpacket/rx.rs`, `src/capture.rs`, `src/stats.rs`

1. Add a privately-tracked accumulator on `AfPacketRx`:

   ```rust
   pub struct AfPacketRx {
       ring: MmapRing,
       fd: OwnedFd,
       current_block: usize,
       expected_seq: u64,
       cumulative_stats: std::sync::atomic::AtomicU64, /* see below */
   }
   ```

   Actually, since `AfPacketRx` is `!Sync` and `stats` needs to be callable from
   `&self`, use `Cell<CaptureStats>` interior mutability for the cumulative copy.

2. New method on `PacketSource` (default impl, non-breaking):

   ```rust
   /// Read accumulated stats since the source was created.
   ///
   /// Unlike [`stats()`](Self::stats), this does not reset kernel counters —
   /// internally it reads the kernel delta and adds to a stored running total.
   ///
   /// Default implementation: calls `stats()` and accumulates. Backends may
   /// override for efficiency.
   fn cumulative_stats(&self) -> Result<CaptureStats, Error> {
       self.stats() // not actually accumulated in default; see AfPacketRx override
   }
   ```

3. `AfPacketRx` overrides:

   ```rust
   fn cumulative_stats(&self) -> Result<CaptureStats, Error> {
       let delta = socket::get_packet_stats(self.fd.as_fd())?;
       let total = self.cumulative.get();
       let new_total = CaptureStats {
           packets: total.packets.saturating_add(delta.tp_packets),
           drops: total.drops.saturating_add(delta.tp_drops),
           freeze_count: total.freeze_count.saturating_add(delta.tp_freeze_q_cnt),
       };
       self.cumulative.set(new_total);
       Ok(new_total)
   }
   ```

4. Document tradeoff: `stats()` returns the delta since last read (kernel
   semantics); `cumulative_stats()` returns total-since-construction by
   accumulating deltas internally.

5. Apply same pattern to `Bridge::stats()` and add `Bridge::cumulative_stats()`
   (closes #16's "optional" side).

### Tests

Unit: not directly testable without a live socket. Integration in
`tests/statistics.rs`:
- Capture some packets, call `cumulative_stats()` twice, assert second call's
  `packets` ≥ first call's `packets`.
- Call `stats()` after `cumulative_stats()`, assert `stats().packets == 0` (just
  reset).

### Migration

`PacketSource` trait gets a new default-implemented method — non-breaking for
implementers.

### Checklist
- [ ] `Cell<CaptureStats>` field on `AfPacketRx`
- [ ] Default `cumulative_stats` on `PacketSource`
- [ ] `AfPacketRx::cumulative_stats` override
- [ ] `Capture::cumulative_stats`
- [ ] `Bridge::cumulative_stats`
- [ ] Integration test
- [ ] Doc updates emphasizing the semantic split
- [ ] CHANGELOG entry under "Added"
