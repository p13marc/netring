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
use crate::packet::PacketDirection;
use crate::stats::CaptureStats;

/// Packets one [`AnyBackend::drain_batch`] call delivers before it returns
/// to the run loop — checked between batches, which are never split (an
/// AF_PACKET block goes back to the kernel whole). Under sustained load
/// the source is readable every time the loop looks: an uncapped drain
/// never returned, starving the loop's timers (sweeps, ticks, telemetry,
/// the stop deadline) and growing the events buffer without bound.
/// Readiness stays set when the budget cuts a drain short, so the loop's
/// next readiness poll resolves at once — after it has yielded to the
/// runtime (see the run loop).
const DRAIN_BUDGET: usize = 4096;

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
    /// No backend: a source retired by `BackendErrorPolicy::SkipSource`, or
    /// one between its old backend's drop and its re-open under `Reopen`
    /// (#212). Never ready, delivers nothing, has no counters.
    Closed,
}

/// What one [`AnyBackend::drain_batch`] call did.
pub(crate) struct Drained {
    /// The last delivered packet's timestamp; `None` when nothing was
    /// delivered (a spurious wake, or an error before the first packet).
    pub(crate) last_ts: Option<Timestamp>,
    /// The budget cut the drain short: more is ready.
    pub(crate) more_ready: bool,
    /// The backend failed — after delivering what `last_ts` covers, which
    /// the caller still dispatches.
    pub(crate) error: Option<Error>,
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
            AnyBackend::Closed => Poll::Pending,
        }
    }

    /// Whether this is the [`AnyBackend::Closed`] placeholder.
    pub(crate) fn is_closed(&self) -> bool {
        matches!(self, AnyBackend::Closed)
    }

    /// Drain the retired batches currently ready on this backend — up to
    /// [`DRAIN_BUDGET`] packets' worth — invoking
    /// `on_packet` with a borrowed [`PacketView`] per packet plus the
    /// frame's direction (AF_PACKET reports it; AF_XDP has none —
    /// `PacketDirection::Unknown(0)`, as the streams do — which is what
    /// the direction-aware loopback dedup needs, #178). Reports the
    /// last packet's timestamp (`None` on a spurious wake), whether the
    /// budget cut the drain short (more is ready), and a backend error —
    /// after whatever was delivered before it, which the caller still
    /// dispatches.
    ///
    /// The readiness guard is held only across the synchronous callback
    /// loop and dropped before this future resolves — no ring borrow
    /// crosses the run loop's later `.await`, preserving `Send`.
    pub(crate) async fn drain_batch(
        &mut self,
        mut on_packet: impl FnMut(PacketView<'_>, PacketDirection),
    ) -> Drained {
        let mut last_ts: Option<Timestamp> = None;
        let mut delivered: usize = 0;
        let error: Option<Error> = match self {
            AnyBackend::AfPacket(cap) => {
                let mut guard = match cap.readable().await {
                    Ok(g) => g,
                    Err(e) => return Drained::failed(e),
                };
                while delivered < DRAIN_BUDGET
                    && let Some(batch) = guard.next_batch()
                {
                    delivered += batch.len();
                    for pkt in &batch {
                        last_ts = Some(pkt.timestamp());
                        // `view()` carries a stripped VLAN tag that is not
                        // in the data (re-insertion off / impossible) and the
                        // wire length (flowscope counts it and gaps what a
                        // snap length cut).
                        on_packet(pkt.view(), pkt.direction());
                    }
                }
                None
            }
            #[cfg(feature = "af-xdp")]
            AnyBackend::Xdp(xdp) => {
                let mut guard = match xdp.readable().await {
                    Ok(g) => g,
                    Err(e) => return Drained::failed(e),
                };
                while delivered < DRAIN_BUDGET
                    && let Some(batch) = guard.next_batch()
                {
                    delivered += batch.len();
                    for pkt in &batch {
                        // AF_XDP frames carry a hardware timestamp + RX metadata
                        // only when the NIC + driver populate it (issue #13);
                        // fall back to now() for the timestamp.
                        let ts = pkt.timestamp().unwrap_or_else(now_ts);
                        last_ts = Some(ts);
                        on_packet(
                            PacketView::new(pkt.data(), ts)
                                .with_wire_len(pkt.data().len())
                                .with_rx_metadata(pkt.rx_metadata()),
                            PacketDirection::Unknown(0),
                        );
                    }
                }
                None
            }
            #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
            AnyBackend::XdpMq(cap) => {
                // Fair round-robin: drain every queue that currently has data,
                // starting after the last-served one. `socket_rx_ready` is a
                // fresh ring probe, so `socket_readable` resolves immediately
                // (no blocking on idle queues).
                let n = cap.socket_count();
                let start = cap.next_cursor();
                let mut error = None;
                for off in 0..n {
                    let i = (start + off) % n;
                    if delivered >= DRAIN_BUDGET || !cap.socket_rx_ready(i) {
                        continue;
                    }
                    let mut guard = match cap.socket_readable(i).await {
                        Ok(g) => g,
                        Err(e) => {
                            // Earlier queues' packets were delivered: hand
                            // them back with the error.
                            error = Some(e);
                            break;
                        }
                    };
                    while delivered < DRAIN_BUDGET
                        && let Some(batch) = guard.next_batch()
                    {
                        delivered += batch.len();
                        for pkt in &batch {
                            let ts = pkt.timestamp().unwrap_or_else(now_ts);
                            last_ts = Some(ts);
                            on_packet(
                                PacketView::new(pkt.data(), ts)
                                    .with_wire_len(pkt.data().len())
                                    .with_rx_metadata(pkt.rx_metadata()),
                                PacketDirection::Unknown(0),
                            );
                        }
                    }
                }
                error
            }
            AnyBackend::Closed => None,
        };
        Drained {
            last_ts,
            more_ready: error.is_none() && delivered >= DRAIN_BUDGET,
            error,
        }
    }

    /// Cumulative [`CaptureStats`] (lifetime totals of the current backend)
    /// **plus** the per-source [`DropBreakdown`](crate::stats::DropBreakdown)
    /// — the un-collapsed "where did packets drop" detail (issue #39).
    /// Returns both from a single counter read so AF_PACKET's destructive
    /// `PACKET_STATISTICS` read isn't double-consumed.
    pub(crate) fn counters(&self) -> Result<(CaptureStats, crate::stats::DropBreakdown)> {
        match self {
            AnyBackend::AfPacket(cap) => {
                let c = cap.get_ref().stats()?;
                let detail = crate::stats::DropBreakdown::AfPacket { freezes: c.freezes };
                Ok((c, detail))
            }
            #[cfg(feature = "af-xdp")]
            AnyBackend::Xdp(xdp) => {
                let s = xdp.statistics()?;
                Ok((s.capture_stats(xdp.get_ref().rx_received()), s.into()))
            }
            #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
            AnyBackend::XdpMq(cap) => cap.counters(),
            AnyBackend::Closed => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "capture source closed",
            ))),
        }
    }
}

impl Drained {
    fn failed(error: Error) -> Self {
        Self {
            last_ts: None,
            more_ready: false,
            error: Some(error),
        }
    }
}

#[cfg(feature = "af-xdp")]
fn now_ts() -> Timestamp {
    Timestamp::from_system_time(std::time::SystemTime::now())
}
