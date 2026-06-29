# Capture backends (`AnyBackend`)

> Design reference for the `AnyBackend` I/O core (shipped in the 0.24 Phase B
> rewrite). This documents the backend enum shape; see `ARCHITECTURE.md` for the
> surrounding data-path design.

## Why an enum, not a `dyn` trait

The `Monitor` run loop must stay `Send` (so `run_for(..)` can be `tokio::spawn`'d,
the 0.23 property) and zero-copy (no per-packet `to_owned`). Two constraints make a
`dyn CaptureBackend` trait the *wrong* tool:

1. **`async fn` in a trait does not yield a `Send` future** (the AFIT/RPITIT
   Send-bound problem). A `dyn` backend with `async fn readable` would silently make
   the run-loop future `!Send`.
2. **`drain_batch(&mut self, f: impl FnMut(PacketView))` is a generic method** →
   not object-safe.

A concrete enum sidesteps both: its `async fn readable` returns a *concrete* future
(`Send` because every arm's future is `Send`), and the generic `drain_batch`
monomorphizes per call site.

```rust
pub enum AnyBackend {                       // arms cfg-gated by backend features
    AfPacket(AsyncCapture<Capture>),
    #[cfg(feature = "af-xdp")] Xdp(AsyncXdpSocket),
    #[cfg(feature = "pcap")]   Pcap(PcapSource),
}

impl AnyBackend {
    /// Await readiness without borrowing the ring (keeps the run loop `Send`).
    pub async fn readable(&mut self) -> Result<()>;
    /// Poll readiness for a multi-backend `select!` (no await, no borrow held).
    pub(crate) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    /// Drain one batch in place; the closure sees zero-copy `PacketView`s. No
    /// await inside — the borrow is released before the next await.
    pub fn drain_batch(&mut self, f: impl FnMut(PacketView<'_>)) -> Result<DrainOutcome>;
    pub fn stats(&self) -> Result<CaptureStats>;
    pub fn set_filter(&self, f: &KernelFilter) -> Result<()>;   // 0.25-A pushdown
    pub fn kind(&self) -> BackendKind;
}
```

The borrowed building blocks already exist on `AsyncCapture`:
`readable() -> ReadableGuard`, `ReadableGuard::next_batch() -> Option<PacketBatch<'_>>`,
and `poll_read_ready_mut(cx)` for the multi-backend readiness `select!`.

## The borrowed, `Send`, zero-copy loop

```text
loop {
  select! {
    _ = shutdown            => break,
    i = ready_backend(&mut backends)  => { /* backend i is readable */ }   // poll_ready, no borrow held
    ... ticks / merge / telemetry ...
  }
  let mut pending = SmallVec<[BoxFuture<Result<Effects>>; 8]>::new();
  backends[i].drain_batch(|view| {        // ZERO-COPY borrow; NO await inside
      track_into(view, &mut events);       // sync
      dispatch_packet_tier / lifecycle / slots (sync mutate + collect async futures into `pending`)
  })?;                                     // <- batch dropped here (ring borrow ends)
  for fut in pending.drain(..) { apply_effects(fut.await?); }   // await + apply AFTER drop
}
```

No `!Sync` ring borrow ever crosses an `.await` ⇒ the future stays `Send`. No packet
is copied (only the already-present owned `events: Vec<FsEvent>` buffer and, when
async handlers exist, the small `pending` future vec).

## Backends

| Arm | `readable` | `drain_batch` | Fanout | Notes |
|---|---|---|---|---|
| **AfPacket** | `AsyncFd` read-ready | TPACKET_v3 block via `ReadableGuard::next_batch` | `PACKET_FANOUT` (Cpu/Hash/Sym) | the universal base; always compiled |
| **Xdp** | `AsyncFd` read-ready | UMEM frames via `consumer_peek`/`read_at` + batched fill refill | per-queue XSKs | zero-copy; copy-mode fallback (B5); hugepage/NUMA UMEM (B5) |
| **Pcap** | always-ready until EOF | one packet per `poll_next` | n/a | folds in the old `replay_loop`; **verifiable without CAP_NET_RAW** |

## Future arm: io_uring ZC-RX (seam, not shipped)

io_uring zero-copy receive (kernel 6.x) splits headers (to the kernel stack) from
payloads (DMA'd to userspace), so the kernel does TCP reassembly *and* you get
zero-copy payloads — the opposite tradeoff from AF_XDP's raw frames, and ideal for
**session-tier** subscriptions. It fits `AnyBackend` as another arm:

```rust
#[cfg(feature = "io-uring")] IoUringZcRx(IoUringRx),   // future
```

`readable` = io_uring completion readiness; `drain_batch` = iterate completed ZC-RX
buffers as `PacketView`s; the buffer ring is refilled on drop (like AF_XDP's fill
ring). Requires NIC header/data-split + flow steering. Not implemented in 0.24 — the
enum is the seam, and the borrowed-loop contract above is exactly what it needs.

## Compatibility

`MonitorBuilder::backend(Backend::AfPacket{..} | Xdp{..} | Pcap{..})` is the new
selector; `interface()` / `fanout()` / `pcap_source()` / `replay()` remain as
`#[deprecated]` shims through 0.24/0.25 and are removed at 1.0 (arch §7).
