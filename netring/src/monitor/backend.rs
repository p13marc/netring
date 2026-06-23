//! `AnyBackend` — the Monitor run loop's capture-backend seam (0.24 Phase B).
//!
//! The run loop is backend-agnostic: it owns a `Vec<AnyBackend>` and drains
//! each through one uniform interface, regardless of whether the bytes come
//! from an AF_PACKET ring or an AF_XDP UMEM. This is the abstraction that
//! lets AF_XDP reach the high-level Monitor (previously the run loop opened
//! AF_PACKET only).
//!
//! ## Why an enum, not a trait
//!
//! The hot path is [`drain_batch`](AnyBackend::drain_batch), which takes
//! `impl FnMut(PacketView)`. A non-object-safe generic method like that
//! can't live on a `dyn Trait`, and an `async fn` in a trait returns a
//! `!Send` future under the AFIT desugaring — both fatal for the run loop's
//! `Send` requirement. A concrete enum sidesteps both: each arm's drain is
//! monomorphized and the future is `Send` because every arm is `Send`.
//!
//! ## Zero-copy + Send contract
//!
//! `drain_batch` holds the backend's readiness guard only for the duration
//! of the synchronous per-packet callback loop, then drops it — the borrow
//! never crosses the `.await` boundary the run loop awaits afterward, which
//! is what keeps `run_for`'s future `Send`. The callback receives a borrowed
//! [`PacketView`]; nothing is copied here (the tracker copies only the
//! metadata it needs). dhat stays Δ 0.

use std::task::{Context, Poll};

use flowscope::{PacketView, Timestamp};

use crate::AsyncCapture;
use crate::error::{Error, Result};
use crate::stats::CaptureStats;

/// A live capture backend behind the Monitor run loop. AF_PACKET today;
/// AF_XDP behind the `af-xdp` feature.
// The AF_PACKET and AF_XDP arms differ in size, but this enum lives in a
// `Vec` with one entry per capture interface (typically one) and sits on the
// per-batch drain hot path — boxing the larger arm would add a pointer-chase
// per `drain_batch` for no practical memory win.
#[allow(clippy::large_enum_variant)]
pub(crate) enum AnyBackend {
    /// AF_PACKET (TPACKET_v3) ring — the always-available base backend.
    AfPacket(AsyncCapture<crate::Capture>),
    /// AF_XDP socket (kernel-bypass). Requires an attached XDP redirect
    /// program to receive packets (see `XdpSocketBuilder`).
    #[cfg(feature = "af-xdp")]
    Xdp(crate::AsyncXdpSocket),
    /// Multi-queue AF_XDP (issue #6 Tier 1): one socket per RX queue behind a
    /// single attached program, drained through a unified fair round-robin.
    /// One backend, internally N sockets — preserves the run loop's
    /// 1-spec↔1-backend invariant (so `Reopen` rebuilds the whole capture).
    #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
    XdpMq(crate::AsyncXdpCapture),
}

impl AnyBackend {
    /// Poll-based readiness, for the run loop's fair round-robin select.
    /// Mirrors `AsyncFd::poll_read_ready_mut` but discards the guard (the
    /// caller re-acquires it via [`drain_batch`](Self::drain_batch)); the
    /// level-triggered fd stays ready so the subsequent drain resolves
    /// immediately.
    pub(crate) fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self {
            AnyBackend::AfPacket(cap) => cap.poll_read_ready_mut(cx).map(|r| match r {
                Ok(_guard) => Ok(()),
                Err(e) => Err(Error::Io(e)),
            }),
            #[cfg(feature = "af-xdp")]
            AnyBackend::Xdp(xdp) => xdp.poll_read_ready_mut(cx).map(|r| match r {
                Ok(_guard) => Ok(()),
                Err(e) => Err(Error::Io(e)),
            }),
            #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
            AnyBackend::XdpMq(cap) => cap.poll_read_ready(cx),
        }
    }

    /// Drain every retired batch currently ready on this backend, invoking
    /// `on_packet` with a borrowed [`PacketView`] per packet. Returns the
    /// last packet's timestamp, or `None` on a spurious wake (no data).
    ///
    /// The readiness guard is held only across the synchronous callback
    /// loop and dropped before this future resolves — no ring borrow
    /// crosses the run loop's later `.await`, preserving `Send`.
    pub(crate) async fn drain_batch(
        &mut self,
        mut on_packet: impl FnMut(PacketView<'_>),
    ) -> Result<Option<Timestamp>> {
        let mut last_ts: Option<Timestamp> = None;
        match self {
            AnyBackend::AfPacket(cap) => {
                let mut guard = cap.readable().await?;
                while let Some(batch) = guard.next_batch() {
                    for pkt in &batch {
                        let ts = pkt.timestamp();
                        last_ts = Some(ts);
                        on_packet(PacketView::new(pkt.data(), ts));
                    }
                }
            }
            #[cfg(feature = "af-xdp")]
            AnyBackend::Xdp(xdp) => {
                let mut guard = xdp.readable().await?;
                while let Some(batch) = guard.next_batch() {
                    for pkt in &batch {
                        // AF_XDP frames carry a hardware timestamp only when
                        // the NIC + driver populate it; fall back to now().
                        let ts = pkt.timestamp().unwrap_or_else(now_ts);
                        last_ts = Some(ts);
                        on_packet(PacketView::new(pkt.data(), ts));
                    }
                }
            }
            #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
            AnyBackend::XdpMq(cap) => {
                // Fair round-robin: drain every queue that currently has data,
                // starting after the last-served one. `socket_rx_ready` is a
                // fresh ring probe, so `socket_readable` resolves immediately
                // (no blocking on idle queues).
                let n = cap.socket_count();
                let start = cap.next_cursor();
                for off in 0..n {
                    let i = (start + off) % n;
                    if !cap.socket_rx_ready(i) {
                        continue;
                    }
                    let mut guard = cap.socket_readable(i).await?;
                    while let Some(batch) = guard.next_batch() {
                        for pkt in &batch {
                            let ts = pkt.timestamp().unwrap_or_else(now_ts);
                            last_ts = Some(ts);
                            on_packet(PacketView::new(pkt.data(), ts));
                        }
                    }
                }
            }
        }
        Ok(last_ts)
    }

    /// Cumulative capture statistics **plus** the per-source
    /// [`DropBreakdown`](crate::stats::DropBreakdown) — the un-collapsed
    /// "where did packets drop" detail (issue #39). Returns both from a
    /// single counter read so AF_PACKET's destructive `tp_drops` read
    /// isn't double-consumed.
    pub(crate) fn detailed_stats(&self) -> Result<(CaptureStats, crate::stats::DropBreakdown)> {
        match self {
            AnyBackend::AfPacket(cap) => {
                let stats = cap.cumulative_stats()?;
                let detail = crate::stats::DropBreakdown::AfPacket {
                    freezes: stats.freeze_count as u64,
                };
                Ok((stats, detail))
            }
            #[cfg(feature = "af-xdp")]
            AnyBackend::Xdp(xdp) => {
                let s = xdp.statistics()?;
                Ok((s.to_capture_stats(), s.into()))
            }
            #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
            AnyBackend::XdpMq(cap) => cap.detailed_stats(),
        }
    }
}

#[cfg(feature = "af-xdp")]
fn now_ts() -> Timestamp {
    Timestamp::from_system_time(std::time::SystemTime::now())
}
