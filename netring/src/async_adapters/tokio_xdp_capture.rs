//! Async multi-queue AF_XDP capture (issue #6, M3).
//!
//! [`AsyncXdpCapture`] is the tokio front for [`XdpCapture`]:
//! it wraps each per-queue socket in an [`AsyncXdpSocket`] (its own `AsyncFd`) and
//! presents a unified readiness + round-robin drain over all of them, holding the
//! shared program + promiscuous guard for the capture's lifetime.
//!
//! This is the **single-reactor** tier (one task drains every queue, fair
//! round-robin) — convenient and correct, but one core. For line rate, the
//! sharded worker-per-queue model uses [`XdpCapture::into_parts`] directly (one
//! socket per thread). The Monitor wires this as `AnyBackend::XdpMq`.

use std::task::{Context, Poll};

use crate::AsyncXdpSocket;
use crate::afxdp::XdpCaptureGuard;
use crate::error::{Error, Result};
use crate::packet::OwnedPacket;
use crate::xdp::XdpCapture;

/// Async, multi-queue AF_XDP capture: one `AsyncFd`-backed socket per RX queue,
/// drained through a unified fair round-robin.
pub struct AsyncXdpCapture {
    sockets: Vec<AsyncXdpSocket>,
    queue_ids: Vec<u32>,
    // Keeps the single attached program + promiscuous guard alive for as long
    // as the sockets exist (dropped after them — field order).
    _guard: XdpCaptureGuard,
    cursor: usize,
}

impl AsyncXdpCapture {
    /// Wrap a built [`XdpCapture`] for async use.
    pub fn new(capture: XdpCapture) -> Result<Self> {
        let queue_ids = capture.queue_ids().to_vec();
        let (sockets, guard) = capture.into_parts();
        let sockets = sockets
            .into_iter()
            .map(AsyncXdpSocket::new)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            sockets,
            queue_ids,
            _guard: guard,
            cursor: 0,
        })
    }

    /// Open a capture on `iface` over **all** RSS queues, promiscuous — the
    /// one-line async full-NIC recipe.
    pub fn open(iface: &str) -> Result<Self> {
        Self::new(XdpCapture::open(iface)?)
    }

    /// The bound queue ids, in socket order.
    pub fn queue_ids(&self) -> &[u32] {
        &self.queue_ids
    }

    /// Number of per-queue sockets.
    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// Whether **every** socket bound in zero-copy mode (issue #6 F2).
    pub fn is_zerocopy(&self) -> bool {
        self.sockets.iter().all(|s| s.get_ref().is_zerocopy())
    }

    /// Poll readiness across all queues: `Ready(Ok(()))` as soon as a socket has
    /// **actual ring data**. Stale `AsyncFd` readiness (the fd signalled but the
    /// ring is empty — e.g. after a prior drain) is cleared so the reactor
    /// re-arms instead of spinning. Used by the Monitor's `AnyBackend::XdpMq`.
    pub(crate) fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        for sock in &mut self.sockets {
            match sock.poll_read_ready_mut(cx) {
                Poll::Ready(Ok(mut guard)) => {
                    if guard.get_inner_mut().rx_poll_ready() {
                        // Real data — leave readiness set so the drain resolves
                        // immediately, and stop (round-robin drain handles the rest).
                        return Poll::Ready(Ok(()));
                    }
                    // Spurious/stale wake: clear so we don't busy-loop.
                    guard.clear_ready();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    /// Await until at least one queue has data.
    pub async fn readable(&mut self) -> Result<()> {
        std::future::poll_fn(|cx| self.poll_read_ready(cx)).await
    }

    /// Drain every queue with data into owned packets, tagged by queue id —
    /// the simple `Send` standalone path. Awaits until at least one queue has
    /// data, then collects all currently-available frames.
    pub async fn recv(&mut self) -> Result<Vec<(u32, OwnedPacket)>> {
        loop {
            self.readable().await?;
            let mut out = Vec::new();
            let n = self.sockets.len();
            for off in 0..n {
                let i = (self.cursor + off) % n;
                if self.sockets[i].get_mut().rx_poll_ready() {
                    let qid = self.queue_ids[i];
                    for p in self.sockets[i].get_mut().recv()? {
                        out.push((qid, p));
                    }
                }
            }
            if !out.is_empty() {
                return Ok(out);
            }
            // All wakes were spurious — loop and re-arm.
        }
    }

    /// Decompose into the per-queue async sockets + the program/promisc guard,
    /// for the worker-per-queue model (move each socket to its own task/core).
    pub fn into_parts(self) -> (Vec<AsyncXdpSocket>, XdpCaptureGuard) {
        (self.sockets, self._guard)
    }
}

/// Helpers used only by the Monitor's `AnyBackend::XdpMq` drain (gated on the
/// `flow`-gated monitor that consumes them, so the `tokio,af-xdp,xdp-loader`
/// build without `flow` doesn't flag them as dead).
#[cfg(feature = "flow")]
impl AsyncXdpCapture {
    /// Fresh (kernel-synced) ring-data probe for socket `i` — the gate the
    /// round-robin drain uses to avoid blocking on not-ready queues.
    pub(crate) fn socket_rx_ready(&mut self, i: usize) -> bool {
        self.sockets[i].get_mut().rx_poll_ready()
    }

    /// Acquire the readiness guard for socket `i` (resolves immediately when the
    /// caller has already confirmed [`socket_rx_ready`](Self::socket_rx_ready)).
    pub(crate) async fn socket_readable(
        &mut self,
        i: usize,
    ) -> Result<crate::async_adapters::tokio_xdp::XdpReadableGuard<'_>> {
        self.sockets[i].readable().await
    }

    /// Advance the round-robin cursor and return its previous value, so each
    /// drain starts after the last-served queue (fairness).
    pub(crate) fn next_cursor(&mut self) -> usize {
        let c = self.cursor;
        if !self.sockets.is_empty() {
            self.cursor = (self.cursor + 1) % self.sockets.len();
        }
        c
    }

    /// Aggregate per-queue `XDP_STATISTICS` into both the unified
    /// [`CaptureStats`](crate::stats::CaptureStats) **and** the
    /// un-collapsed [`DropBreakdown`](crate::stats::DropBreakdown) in one
    /// pass over the sockets (issue #39). `XDP_STATISTICS` is
    /// non-destructive, so summing is monotonic and repeatable.
    pub(crate) fn detailed_stats(
        &self,
    ) -> Result<(crate::stats::CaptureStats, crate::stats::DropBreakdown)> {
        let mut agg = crate::afxdp::XdpStats::default();
        for s in &self.sockets {
            agg = agg.saturating_add(s.statistics()?);
        }
        Ok((agg.to_capture_stats(), agg.into()))
    }
}
