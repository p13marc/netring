# Phase 5 — API tightening

One genuinely breaking change (#19) plus three doc/safety hardenings. Bundle all
four into the same `0.3.0` release if possible.

---

## Fix #19 — `attach_ebpf_filter` takes `RawFd` instead of `AsFd` *(breaking)*

### Problem

`src/afpacket/rx.rs:58` and `src/capture.rs:97`:

```rust
pub fn attach_ebpf_filter(&self, prog_fd: std::os::fd::RawFd) -> Result<(), Error>
```

The whole crate is otherwise rigorous about `OwnedFd`/`BorrowedFd`/`AsFd`. Taking
a raw fd:

- Makes the lifetime of `prog_fd` invisible to the type system — a user can pass
  the fd of an `aya::Program` that's later dropped, leaving netring's reference
  dangling.
- Encourages double-close patterns (the user must remember not to close
  `prog_fd` while netring still has it bound).
- Inconsistent with `Capture::as_fd() -> BorrowedFd`.

### Plan

**Files:** `src/afpacket/rx.rs`, `src/capture.rs`, `src/afpacket/filter.rs`,
`src/afpacket/fanout.rs`

1. Change the public signatures:

   ```rust
   // src/afpacket/rx.rs
   impl AfPacketRx {
       pub fn attach_ebpf_filter<F: AsFd>(&self, prog: F) -> Result<(), Error> {
           filter::attach_ebpf_socket_filter(self.fd.as_fd(), prog.as_fd())
       }
   }

   // src/capture.rs
   impl Capture {
       pub fn attach_ebpf_filter<F: AsFd>(&self, prog: F) -> Result<(), Error> {
           self.rx.attach_ebpf_filter(prog)
       }
   }
   ```

2. Update the internal helpers:

   ```rust
   // src/afpacket/filter.rs
   pub(crate) fn attach_ebpf_socket_filter(
       sock: BorrowedFd<'_>,
       prog: BorrowedFd<'_>,
   ) -> Result<(), Error> {
       let prog_fd = prog.as_raw_fd();
       raw_setsockopt(sock, libc::SOL_SOCKET, libc::SO_ATTACH_BPF, &prog_fd, "SO_ATTACH_BPF")
   }

   // src/afpacket/fanout.rs
   pub(crate) fn attach_fanout_ebpf(
       sock: BorrowedFd<'_>,
       prog: BorrowedFd<'_>,
   ) -> Result<(), Error> {
       let prog_fd = prog.as_raw_fd();
       raw_setsockopt(sock, ffi::SOL_PACKET, ffi::PACKET_FANOUT_DATA, &prog_fd, "PACKET_FANOUT_DATA")
   }
   ```

3. Document that `aya` users pass `prog.fd()` which implements `AsFd` (since
   recent aya versions); for older aya, they wrap with `unsafe { BorrowedFd::borrow_raw(raw) }`.

4. Migration note in CHANGELOG and docs:

   ```markdown
   ## 0.3.0
   
   ### Breaking
   - `Capture::attach_ebpf_filter` and `AfPacketRx::attach_ebpf_filter` now take
     `impl AsFd` instead of `RawFd`. Migration:
     ```diff
     - cap.attach_ebpf_filter(prog.fd().as_raw_fd())?;
     + cap.attach_ebpf_filter(prog.fd())?;
     ```
   ```

5. Update `examples/ebpf_filter.rs` to use the new signature.

### Tests

Unit: a `cfg(test)` mock that creates an arbitrary fd via `socketpair`, wraps it
in `OwnedFd`, and passes to `attach_ebpf_filter`. Setsockopt will fail (not a real
BPF program) but the type-check covers the API surface.

### Migration

**Hard breaking.** Bump to `0.3.0`. Bundle with Phase 5's other items.

### Checklist
- [ ] Change `AfPacketRx::attach_ebpf_filter` signature
- [ ] Change `Capture::attach_ebpf_filter` signature
- [ ] Refactor internal helper signatures
- [ ] Update `attach_fanout_ebpf` (paired with Fix #8)
- [ ] Update `examples/ebpf_filter.rs`
- [ ] CHANGELOG entry under "Breaking"
- [ ] Update docstrings with migration tip

---

## Fix #23 — Document `source_ll_addr` truncation

### Problem

`src/packet.rs:240`: `&sll.sll_addr[..len.min(8)]`. `sockaddr_ll.sll_addr` is fixed
`[u8; 8]`. For Ethernet (6-byte MAC) this is fine. For InfiniBand (20-byte LLE) the
kernel truncates to 8 silently. Users get partial address with no warning.

### Plan

**Files:** `src/packet.rs`

Update the docstring:

```rust
/// Source link-layer address from kernel ring metadata.
///
/// Returns up to 8 bytes; this is the size of `sockaddr_ll::sll_addr` in the
/// Linux kernel. For 6-byte Ethernet MAC this is sufficient; for longer
/// link-layer addresses (e.g., InfiniBand's 20-byte LLE), the result is
/// truncated by the kernel itself — netring just exposes what the kernel
/// provides. Use `RTM_GETLINK` netlink for the full address.
///
/// The slice length matches `sockaddr_ll::sll_halen` (clamped to 8).
pub fn source_ll_addr(&self) -> &[u8] {
    let sll_offset = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>());
    let hdr_ptr = self.hdr as *const ffi::tpacket3_hdr as *const u8;
    let sll_ptr = hdr_ptr.map_addr(|a| a + sll_offset);
    let sll = unsafe { &*(sll_ptr as *const ffi::sockaddr_ll) };
    let len = sll.sll_halen as usize;
    &sll.sll_addr[..len.min(8)]
}
```

### Tests

None — doc-only.

### Checklist
- [ ] Expand docstring
- [ ] CHANGELOG entry under "Changed (docs)"

---

## Fix #25 — `AsyncCapture::wait_readable` race window

### Problem

`src/async_adapters/tokio_adapter.rs:79-83`:

```rust
pub async fn wait_readable(&self) -> Result<(), Error> {
    let mut guard = self.inner.readable().await.map_err(Error::Io)?;
    guard.clear_ready();
    Ok(())
}
```

`clear_ready` is called eagerly, before the user has done any I/O. If the user
then calls `next_batch()` and gets `Some(batch)`, they consume one block. If
another block was retired between `wait_readable()` returning and `next_batch()`
running, the AsyncFd state was already cleared — the next `wait_readable()` will
re-arm via epoll, so we don't lose the wakeup, but we do an extra epoll round trip.

The owned `recv()` path uses `clear_ready()` only when `next_batch()` returns
`None` — which is the canonical pattern.

### Plan

**Files:** `src/async_adapters/tokio_adapter.rs`

Two fixes:

1. **Tighten `wait_readable` semantics** by returning a guard the user explicitly
   interacts with:

   ```rust
   /// Guard returned by `readable()`.
   ///
   /// Holds the AsyncFd readiness flag. Call `next_batch()` (zero-copy) or
   /// `recv_batch()` (copies). If neither yields data, call `not_ready()` to
   /// arm the next epoll wait.
   pub struct ReadableGuard<'a, S: PacketSource + AsRawFd> {
       guard: tokio::io::unix::AsyncFdReadyMutGuard<'a, S>,
   }

   impl<'a, S: PacketSource + AsRawFd> ReadableGuard<'a, S> {
       /// Try to receive a zero-copy batch; clears readiness and returns None
       /// if no batch is currently available (re-arms epoll for next call).
       pub fn next_batch(&mut self) -> Option<PacketBatch<'_>> {
           let inner = self.guard.get_inner_mut();
           match inner.next_batch() {
               Some(b) => Some(b),
               None => { self.guard.clear_ready(); None }
           }
       }
   }

   impl<S: PacketSource + AsRawFd> AsyncCapture<S> {
       /// Wait until the socket is readable and return a guard for batch retrieval.
       pub async fn readable(&mut self) -> Result<ReadableGuard<'_, S>, Error> {
           let guard = self.inner.readable_mut().await.map_err(Error::Io)?;
           Ok(ReadableGuard { guard })
       }
   }
   ```

2. **Deprecate `wait_readable`** with a hint to use `readable()`:

   ```rust
   #[deprecated(since = "0.3.0", note = "Use `readable().await?.next_batch()` instead — eliminates the race window")]
   pub async fn wait_readable(&self) -> Result<(), Error> { ... }
   ```

3. Update `examples/async_capture.rs` to use the new pattern.

### Tests

Hard to test the race directly. Add a doctest illustrating the new pattern; rely
on tokio's existing `AsyncFd` test coverage for the underlying readiness logic.

### Migration

Non-breaking (deprecation only).

### Checklist
- [ ] `ReadableGuard` type
- [ ] `AsyncCapture::readable` method
- [ ] Deprecate `wait_readable`
- [ ] Update example
- [ ] Doctest for new pattern
- [ ] CHANGELOG entry under "Added" (readable/Guard) and "Deprecated"

---

## Fix #26 — Promote `Capture::packets` soundness warning to public docs

### Problem

`src/capture.rs:410-430` has a careful `// SAFETY:` comment about lifetime erasure
and a buried warning that `iter.collect::<Vec<_>>()` is unsound. Users reading
rustdoc for `Capture::packets` see only `impl Iterator<Item = Packet<'_>>` and may
collect unaware.

This is partially addressed by Fix #4 (rustdoc moved up); document standalone for
trackability.

### Plan

**Files:** `src/capture.rs`

Already drafted in Fix #4. Verbatim docstring on `Capture::packets()`:

```rust
/// Blocking iterator over received packets.
///
/// Handles block advancement and retirement automatically. Each
/// [`Packet`] is a zero-copy view into the mmap ring buffer.
///
/// # Soundness — do not collect across blocks
///
/// `Packet<'_>` borrows from the *current* ring block. The iterator returns a
/// block to the kernel before yielding packets from the next block, so any
/// `Packet` retained from a prior block becomes a dangling reference.
///
/// **Do not** do this:
/// ```no_run
/// # let mut cap = netring::Capture::new("lo").unwrap();
/// // ✗ UNSOUND: packets from earlier blocks are invalidated as the iterator advances.
/// let pkts: Vec<_> = cap.packets().take(1000).collect();
/// ```
///
/// Use [`Packet::to_owned()`] if you need to retain a packet:
/// ```no_run
/// # let mut cap = netring::Capture::new("lo").unwrap();
/// // ✓ Sound: each packet is copied out of the ring before the iterator advances.
/// let owned: Vec<_> = cap.packets().take(1000).map(|p| p.to_owned()).collect();
/// ```
///
/// # Iteration timeout
///
/// The iterator blocks (using [`poll_timeout`](CaptureBuilder::poll_timeout)) and
/// retries indefinitely; it returns `None` only on I/O error. Use
/// [`PacketIter::take_error()`] after iteration to inspect any failure.
///
/// For deadline-bounded loops, use the low-level
/// [`next_batch_blocking()`](crate::PacketSource::next_batch_blocking) directly.
```

### Tests

Doctest above is `no_run`; add one `compile_fail` if we want to enforce statically
that `.collect()` would fail. In practice the lifetime erasure makes this hard to
catch at compile time — that's exactly why the warning is doc-level.

### Checklist
- [ ] Update `Capture::packets` rustdoc
- [ ] CHANGELOG entry under "Changed (docs)"
