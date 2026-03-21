# Phase 6: Async Integration & Channel Adapter

## Goal

Add tokio `AsyncFd` adapter and runtime-agnostic thread+channel adapter behind feature flags.

## Prerequisites

Phases 1-5 complete.

## Cargo.toml Changes

```toml
[features]
tokio = ["dep:tokio"]
channel = ["dep:crossbeam-channel"]

[dependencies]
tokio = { version = "1", features = ["io-util", "net"], optional = true }
crossbeam-channel = { version = "0.5", optional = true }
```

## Files

### src/async/mod.rs (new)

**Note:** `async` is a Rust keyword. In `src/lib.rs`, declare as `pub mod r#async;`.
Users import via `netring::r#async::AsyncCapture` or convenience re-exports.

```rust
#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "channel")]
pub mod channel;
```

### src/async/tokio.rs (new) — feature: `tokio`

**AsyncCapture<S: PacketSource = AfPacketRx>:**
- Field: `inner: tokio::io::unix::AsyncFd<S>`
- `new(source: S) -> Result<Self, Error>` — wraps in AsyncFd
- `recv(&mut self) -> Result<PacketBatch<'_>, Error>`:
  ```
  loop {
      if let Some(batch) = self.inner.get_mut().next_batch() {
          return Ok(batch);
      }
      let mut guard = self.inner.readable().await?;
      guard.clear_ready();
  }
  ```
- `get_ref()`, `get_mut()`, `into_inner()`
- `impl AsFd` — delegates to inner source

**AsyncPacketSource impl** (native async fn in trait — no proc macro):
```rust
impl<S: PacketSource> AsyncPacketSource for AsyncCapture<S> {
    async fn next_batch(&mut self) -> Result<PacketBatch<'_>, Error> {
        self.recv().await
    }
}
```

**Key design notes:**
- AF_PACKET fd is blocking by default, but AsyncFd doesn't need non-blocking because we never call blocking syscalls — `next_batch()` only reads mmap'd block_status (no syscall)
- `clear_ready()` is critical for edge-triggered epoll: re-arms readiness notification
- `PacketBatch<'_>` must be consumed before next `recv()` (enforced by `&mut self`)

### src/traits.rs (modify) — add AsyncPacketSource

```rust
#[cfg(feature = "tokio")]
pub trait AsyncPacketSource: AsFd {
    async fn next_batch(&mut self) -> Result<PacketBatch<'_>, Error>;
}
```

Native `async fn` in traits — stable since Rust 1.75, no `#[async_trait]` needed.

### src/async/channel.rs (new) — feature: `channel`

**ChannelCapture:**
- Fields: `receiver: Receiver<OwnedPacket>`, `handle: Option<JoinHandle<()>>`, `stop: Arc<AtomicBool>`
- `spawn(interface: &str, capacity: usize) -> Result<Self, Error>`:
  1. Create AfPacketRx in current thread (errors propagate)
  2. Create bounded crossbeam channel
  3. Spawn thread:
     ```
     while !stop.load(Relaxed) {
         match rx.next_batch_blocking(100ms) {
             Ok(Some(batch)) => {
                 for pkt in &batch { sender.send(pkt.to_owned()); }
             }
             Ok(None) => continue,
             Err(_) => return,
         }
     }
     ```
- `recv() -> Result<OwnedPacket, RecvError>` — blocking receive
- `try_recv() -> Result<OwnedPacket, TryRecvError>` — non-blocking
- `Iterator for &ChannelCapture` — `type Item = OwnedPacket`, `next()` calls `recv().ok()`
- `Drop`: set stop flag, join thread

**Thread safety:** ChannelCapture is Send + Sync automatically (Receiver + Arc<AtomicBool>).

### src/lib.rs (modify)

```rust
#[cfg(any(feature = "tokio", feature = "channel"))]
pub mod r#async;

// Convenience re-export
#[cfg(feature = "channel")]
pub mod channel {
    pub use crate::r#async::channel::ChannelCapture;
}
```

## Testing

**Unit tests:**
- Compile-time: verify AsyncCapture is Send when S: Send
- Verify ChannelCapture is Send + Sync

**Integration tests (CAP_NET_RAW + feature flags):**
- `#[tokio::test] test_async_recv`: build AsyncCapture on loopback, send packets, recv().await
- `test_channel_recv`: spawn ChannelCapture, send packets, recv() returns OwnedPacket
- `test_channel_drop_stops_thread`: drop handle, verify thread terminates

## Potential Challenges

1. **AsyncFd edge-triggered**: must clear_ready() and re-check, not assume batch is ready after wakeup
2. **Channel backpressure**: if consumer is slow, bounded channel blocks the capture thread — acceptable, drops happen at the ring level (detected via stats)
3. **Thread join in Drop**: if capture thread panics, `handle.join()` returns Err — swallow in destructor
