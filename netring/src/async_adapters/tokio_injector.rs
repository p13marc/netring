//! Async packet injection using tokio [`AsyncFd`].
//!
//! Pairs with [`AsyncCapture`](crate::AsyncCapture): the same `AsyncFd`-based
//! readiness machinery, but for the TX path. `AsyncInjector::send` waits on
//! `POLLOUT` (kernel reclaims a TX slot) when the ring is full, instead of
//! returning `None` and forcing the caller to retry.
//!
//! # Example
//!
//! ```no_run
//! # async fn _ex() -> Result<(), netring::Error> {
//! use netring::{AsyncInjector, Injector};
//!
//! let mut atx = AsyncInjector::new(Injector::open("lo")?)?;
//! atx.send(&[0xff; 64]).await?;
//! atx.flush().await?;
//! # Ok(()) }
//! ```

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::Duration;

use tokio::io::unix::AsyncFd;

use crate::afpacket::tx::Injector;
use crate::error::Error;

/// Async wrapper around [`Injector`] using tokio's [`AsyncFd`].
///
/// Provides three async-friendly entry points:
///
/// - [`send`](Self::send) — copies a packet into a TX slot, waiting on
///   `POLLOUT` if the ring is full. Returns once the slot is queued.
/// - [`flush`](Self::flush) — kicks the kernel to drain queued frames.
/// - [`wait_drained`](Self::wait_drained) — awaits `POLLOUT` until every
///   queued frame has been transmitted (or the timeout expires).
///
/// # Cancel safety
///
/// All three methods are cancel-safe: dropping the future between awaits
/// abandons the readiness wait without losing in-flight frames. Frames
/// already `slot.send()`'d before cancellation remain queued and will be
/// transmitted by the next `flush()`.
pub struct AsyncInjector {
    inner: AsyncFd<Injector>,
}

impl AsyncInjector {
    /// Wrap an [`Injector`] in an async adapter.
    ///
    /// Registers the source's fd with tokio's reactor for `POLLOUT` and
    /// `POLLIN` (the kernel signals slot reclamation via `POLLOUT`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if `AsyncFd` registration fails.
    pub fn new(tx: Injector) -> Result<Self, Error> {
        let fd = AsyncFd::with_interest(tx, tokio::io::Interest::WRITABLE).map_err(Error::Io)?;
        Ok(Self { inner: fd })
    }

    /// Open an async injector on `interface` with default settings.
    ///
    /// One-liner shortcut for `AsyncInjector::new(Injector::open(interface)?)`.
    /// For configured injectors, use the builder via
    /// `AsyncInjector::new(Injector::builder()...build()?)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// let mut tx = netring::AsyncInjector::open("eth0")?;
    /// tx.send(&[0xff; 64]).await?;
    /// tx.flush().await?;
    /// # Ok(()) }
    /// ```
    pub fn open(interface: &str) -> Result<Self, Error> {
        Self::new(Injector::open(interface)?)
    }

    /// Queue a packet for transmission, waiting if the TX ring is full.
    ///
    /// Equivalent to repeatedly trying [`Injector::allocate`] +
    /// `slot.set_len(len) + slot.send()` and awaiting `POLLOUT` between
    /// failed attempts. Returns once the frame is queued — call
    /// [`flush`](Self::flush) to actually kick the kernel.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::Config`] if `data.len()` exceeds the TX frame
    ///   capacity (set at builder time).
    /// - Returns [`Error::Io`] if the underlying readiness wait fails.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        let cap = self.inner.get_ref().frame_capacity();
        if data.len() > cap {
            return Err(Error::Config(format!(
                "packet length {} exceeds TX frame capacity {}",
                data.len(),
                cap
            )));
        }
        loop {
            // Try non-blocking allocate first — common-case fast path.
            if let Some(mut slot) = self.inner.get_mut().allocate(data.len()) {
                slot.data_mut()[..data.len()].copy_from_slice(data);
                slot.set_len(data.len());
                slot.send();
                return Ok(());
            }
            // Ring full: wait for kernel to reclaim a slot via POLLOUT.
            let mut guard = self.inner.writable_mut().await.map_err(Error::Io)?;
            // The reclamation might be partial; clear_ready re-arms the
            // reactor so the next iteration's writable_mut() will block.
            // We do not consult pending_count here (would re-borrow self.inner
            // while guard is alive); the next allocate() attempt will tell us.
            guard.clear_ready();
            drop(guard);
        }
    }

    /// Kick the kernel to transmit queued frames.
    ///
    /// Forwards to [`Injector::flush`]; awaits no I/O readiness today
    /// (the underlying syscall is non-blocking with `EAGAIN`/`ENOBUFS`
    /// reported as transient success). Async signature reserves room for
    /// future enhancements.
    pub async fn flush(&mut self) -> Result<usize, Error> {
        self.inner.get_mut().flush()
    }

    /// Wait until every queued frame has been transmitted.
    ///
    /// Polls `POLLOUT` (kernel signals slot reclamation) and re-checks
    /// [`Injector::pending_count`] until it hits zero or `timeout`
    /// elapses. Use before drop when you need to observe transmission
    /// failures or guarantee the kernel has finished.
    pub async fn wait_drained(&mut self, timeout: Duration) -> Result<(), Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.inner.get_ref().pending_count() == 0 {
                return Ok(());
            }
            let remaining = match deadline.checked_duration_since(tokio::time::Instant::now()) {
                Some(r) => r,
                None => {
                    return Err(Error::Io(std::io::Error::from(
                        std::io::ErrorKind::TimedOut,
                    )));
                }
            };
            // Cap each wait so we re-check pending_count even on partial
            // reclamation events.
            let slice = remaining.min(Duration::from_millis(10));
            tokio::select! {
                ready = self.inner.writable_mut() => {
                    let mut guard = ready.map_err(Error::Io)?;
                    guard.clear_ready();
                }
                _ = tokio::time::sleep(slice) => {}
            }
        }
    }

    /// 0.25 W3: transmit every frame yielded by `stream`, optionally
    /// rate-limited by a [`TxPacer`]. The TX-side counterpart to the RX
    /// streaming adapters (`flow_stream` et al.) — feed it any
    /// `Stream<Item = impl AsRef<[u8]>>` (an `mpsc` of frames, a replayed
    /// pcap, a generator) and it sends + flushes each, pacing between frames
    /// when a pacer is supplied. Returns the number of frames sent.
    ///
    /// ```no_run
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// use netring::{AsyncInjector, TxPacer};
    /// let frames = futures::stream::iter((0..1000).map(|_| vec![0xffu8; 64]));
    /// let mut tx = AsyncInjector::open("eth0")?;
    /// // Cap to 10k packets/sec.
    /// tx.send_stream(frames, Some(TxPacer::packets_per_second(10_000.0))).await?;
    /// # Ok(()) }
    /// ```
    pub async fn send_stream<S, B>(
        &mut self,
        stream: S,
        mut pacer: Option<TxPacer>,
    ) -> Result<usize, Error>
    where
        S: futures_core::Stream<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut stream = std::pin::pin!(stream);
        let mut sent = 0usize;
        while let Some(frame) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
            let bytes = frame.as_ref();
            if let Some(p) = pacer.as_mut() {
                let wait = p.acquire(bytes.len(), std::time::Instant::now());
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }
            self.send(bytes).await?;
            self.flush().await?;
            sent += 1;
        }
        Ok(sent)
    }

    /// 0.25 W3: read the next egress timestamp from the error queue
    /// (non-blocking). Forwards to [`Injector::read_tx_timestamp`]; requires
    /// the injector to have been built with `tx_timestamps(true)`. Returns
    /// `None` if no timestamp is queued yet — poll after `flush()` /
    /// `wait_drained()`.
    pub fn read_tx_timestamp(&self) -> Option<crate::Timestamp> {
        self.inner.get_ref().read_tx_timestamp()
    }

    /// Borrow the inner sink (e.g., for `cumulative_stats`-style accessors).
    pub fn get_ref(&self) -> &Injector {
        self.inner.get_ref()
    }

    /// Mutable inner-sink access.
    pub fn get_mut(&mut self) -> &mut Injector {
        self.inner.get_mut()
    }

    /// Unwrap into the inner sink.
    pub fn into_inner(self) -> Injector {
        self.inner.into_inner()
    }

    // ── Inherent passthroughs to Injector ─────────────────────────────
    //
    // Saves a `use netring::PacketSink;` (or direct field access via
    // `get_ref()`) at the call site for the most common observability
    // accessors.

    /// Maximum payload bytes that fit in a single TX frame.
    /// See [`Injector::frame_capacity`].
    #[inline]
    pub fn frame_capacity(&self) -> usize {
        self.inner.get_ref().frame_capacity()
    }

    /// Total number of frames in the TX ring.
    /// See [`Injector::frame_count`].
    #[inline]
    pub fn frame_count(&self) -> usize {
        self.inner.get_ref().frame_count()
    }

    /// Slots currently `TP_STATUS_AVAILABLE` (reclaimed by kernel).
    /// See [`Injector::available_slots`].
    pub fn available_slots(&self) -> usize {
        self.inner.get_ref().available_slots()
    }

    /// Slots currently `TP_STATUS_WRONG_FORMAT` (kernel-rejected).
    /// See [`Injector::rejected_slots`].
    pub fn rejected_slots(&self) -> usize {
        self.inner.get_ref().rejected_slots()
    }

    /// Slots in `TP_STATUS_SEND_REQUEST` / `TP_STATUS_SENDING`.
    /// See [`Injector::pending_count`].
    pub fn pending_count(&self) -> usize {
        self.inner.get_ref().pending_count()
    }
}

impl AsFd for AsyncInjector {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

impl AsRawFd for AsyncInjector {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

/// 0.25 W3: token-bucket transmit pacer for [`AsyncInjector::send_stream`].
///
/// Caps the send rate to a target in **packets/sec**
/// ([`packets_per_second`](Self::packets_per_second)) or **bits/sec**
/// ([`bits_per_second`](Self::bits_per_second)), smoothing short bursts up to
/// the bucket depth. Pure virtual-time logic — no I/O — so it's unit-tested by
/// feeding it timestamps; `send_stream` drives it with the wall clock.
#[derive(Debug, Clone)]
pub struct TxPacer {
    /// Refill rate in tokens/sec (tokens are packets or bits per `cost_bits`).
    rate: f64,
    /// Bucket capacity (tokens).
    burst: f64,
    /// Current tokens.
    tokens: f64,
    /// Last refill instant (`None` until the first `acquire`).
    last: Option<std::time::Instant>,
    /// When true a frame costs `len*8` tokens (bits/sec); else 1 token (pps).
    cost_bits: bool,
}

impl TxPacer {
    fn new(rate: f64, burst: f64, cost_bits: bool) -> Self {
        let burst = burst.max(1.0);
        Self {
            rate: rate.max(f64::MIN_POSITIVE),
            burst,
            tokens: burst,
            last: None,
            cost_bits,
        }
    }

    /// Pace to `pps` packets per second (burst defaults to one second's worth).
    pub fn packets_per_second(pps: f64) -> Self {
        Self::new(pps, pps, false)
    }

    /// Pace to `bps` bits per second (burst defaults to one second's worth).
    pub fn bits_per_second(bps: f64) -> Self {
        Self::new(bps, bps, true)
    }

    /// Override the bucket depth (max tokens that can accrue while idle).
    pub fn with_burst(mut self, burst: f64) -> Self {
        self.burst = burst.max(1.0);
        self.tokens = self.burst;
        self
    }

    /// Token cost of a `len`-byte frame under this pacer's unit.
    fn cost(&self, len: usize) -> f64 {
        if self.cost_bits {
            (len as f64) * 8.0
        } else {
            1.0
        }
    }

    /// How long to wait before a `len`-byte frame may be sent, consuming its
    /// tokens. `Duration::ZERO` when the bucket already has enough. `now` is
    /// injected so the logic is deterministic under test.
    pub fn acquire(&mut self, len: usize, now: std::time::Instant) -> Duration {
        if let Some(last) = self.last {
            let elapsed = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        }
        self.last = Some(now);
        let cost = self.cost(len);
        if self.tokens >= cost {
            self.tokens -= cost;
            Duration::ZERO
        } else {
            // Pre-spend: drain the bucket and wait out the deficit. The next
            // `acquire`'s refill (measured from this same `now`) makes the
            // accounting self-consistent.
            let deficit = cost - self.tokens;
            self.tokens = 0.0;
            Duration::from_secs_f64(deficit / self.rate)
        }
    }
}

#[cfg(test)]
mod pacer_tests {
    use super::TxPacer;
    use std::time::{Duration, Instant};

    #[test]
    fn first_burst_is_free_then_paces() {
        let t0 = Instant::now();
        // 100 pps, burst 1 → first frame free, next must wait ~10ms.
        let mut p = TxPacer::packets_per_second(100.0).with_burst(1.0);
        assert_eq!(
            p.acquire(64, t0),
            Duration::ZERO,
            "first frame within burst"
        );
        let wait = p.acquire(64, t0);
        assert!(wait > Duration::ZERO, "second back-to-back frame must wait");
        // ~10ms at 100pps; allow slack for float.
        assert!(
            (wait.as_secs_f64() - 0.01).abs() < 1e-3,
            "expected ~10ms, got {wait:?}"
        );
    }

    #[test]
    fn refills_over_time_no_wait_after_interval() {
        let t0 = Instant::now();
        let mut p = TxPacer::packets_per_second(100.0).with_burst(1.0);
        let _ = p.acquire(64, t0);
        // 20ms later, ≥1 token has refilled → no wait.
        let t1 = t0 + Duration::from_millis(20);
        assert_eq!(p.acquire(64, t1), Duration::ZERO);
    }

    #[test]
    fn bits_per_second_costs_scale_with_frame_size() {
        let t0 = Instant::now();
        // 8000 bps, burst 8000 bits = 1000 bytes. A 1000-byte frame (8000 bits)
        // drains the bucket; the next same-size frame waits ~1s.
        let mut p = TxPacer::bits_per_second(8000.0).with_burst(8000.0);
        assert_eq!(p.acquire(1000, t0), Duration::ZERO);
        let wait = p.acquire(1000, t0);
        assert!(
            (wait.as_secs_f64() - 1.0).abs() < 1e-2,
            "expected ~1s, got {wait:?}"
        );
    }
}
