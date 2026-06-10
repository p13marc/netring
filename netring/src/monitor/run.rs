//! Run loop for the 0.20 [`Monitor`].
//!
//! Single-stream over a single [`AsyncCapture`]; the per-CPU
//! sharded version lands in Phase F. Each iteration:
//!
//! 1. await a packet batch from the capture,
//! 2. feed each packet to the flowscope driver and translate the
//!    resulting lifecycle events into typed `FlowStarted<P>` /
//!    `FlowEnded<P>` / `FlowEstablished<P>` / `AnyFlowAnomaly`
//!    payloads dispatched through the handler table,
//! 3. drain each protocol-slot's typed parser messages and
//!    dispatch them.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use flowscope::L4Proto;
use flowscope::driver::Event as FsEvent;
use futures_core::Stream;

use crate::AsyncCapture;
use crate::OwnedPacket;
use crate::anomaly::sink::AnomalySink;
use crate::async_adapters::tokio_adapter::PacketStream;
use crate::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
use crate::error::Result;
use crate::monitor::Monitor;
use crate::monitor::dispatcher::Dispatcher;
use crate::protocol::FlowKey;
#[cfg(feature = "icmp")]
use crate::protocol::builtin::Icmp;
use crate::protocol::builtin::{Tcp, Udp};
use crate::protocol::event_typed::{AnyFlowAnomaly, FlowEnded, FlowEstablished, FlowStarted};

/// How long to keep the run loop alive.
pub(crate) enum StopCondition {
    /// Stop when wall-clock reaches this deadline.
    Deadline(Instant),
    /// Stop on Ctrl-C / SIGTERM. Available only when the tokio
    /// `signal` feature is on; today that's transitively enabled
    /// by netring's `tokio` feature.
    Signal,
}

pub(crate) async fn run_loop(monitor: Monitor, stop: StopCondition) -> Result<()> {
    let Monitor {
        interfaces,
        mut driver,
        mut dispatcher,
        mut protocol_slots,
        mut state_map,
        mut counters,
        mut sink,
        tick_handlers: _, // Phase F.2 lights this up; F.1 accepts the registration only
    } = monitor;

    // Phase F.1: open one AsyncCapture per interface. The order
    // matches the builder's `.interfaces([...])` order; each event
    // gets the corresponding `SourceIdx`. A single-interface
    // monitor (the common case) opens exactly one ring — the
    // round-robin select reduces to a one-armed select with the
    // same latency as the prior single-cap path.
    let mut streams: Vec<PacketStream<_>> = Vec::with_capacity(interfaces.len());
    for iface in &interfaces {
        let cap = AsyncCapture::open(iface)?;
        streams.push(cap.into_stream());
    }

    let mut events: Vec<FsEvent<FlowKey>> = Vec::with_capacity(64);
    let mut shutdown = ShutdownSignal::new(stop);
    let mut rr_anchor: usize = 0;

    loop {
        let next = tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            packet = next_packet(&mut streams, &mut rr_anchor) => packet,
        };
        let (source_idx, batch) = match next {
            Some((i, Ok(b))) => (i, b),
            Some((_, Err(e))) => return Err(e),
            None => break, // all streams exhausted
        };
        let source = SourceIdx(source_idx as u8);

        for pkt in batch {
            let view = flowscope::PacketView::new(&pkt.data, pkt.timestamp);

            // (1) Lifecycle events from the central tracker.
            events.clear();
            driver.track_into(view, &mut events);

            for evt in events.drain(..) {
                dispatch_lifecycle(
                    &mut dispatcher,
                    sink.as_mut(),
                    &mut state_map,
                    &mut counters,
                    evt.clone(),
                    source,
                )?;
                dispatch_lifecycle_async(&mut dispatcher, evt).await?;
            }

            // (2) Typed messages from each registered slot.
            for slot in &mut protocol_slots {
                let mut ctx = Ctx::new(
                    None,
                    pkt.timestamp,
                    source,
                    &mut state_map,
                    sink.as_mut(),
                    &mut counters,
                );
                slot.drain_and_dispatch(&mut dispatcher, &mut ctx)?;
            }
        }
    }

    Ok(())
}

/// Round-robin poll across the N capture streams. Returns
/// `Some((source_idx, batch))` on the next ready stream, or
/// `None` when every stream is exhausted.
///
/// The poll is fair: `anchor` records the index just past the
/// last successful batch, so the next call starts the scan there.
/// A chatty stream can't starve the quieter ones — even if every
/// stream is always ready, we cycle through them.
async fn next_packet<S>(
    streams: &mut [PacketStream<S>],
    anchor: &mut usize,
) -> Option<(usize, Result<Vec<OwnedPacket>>)>
where
    S: crate::traits::PacketSource + std::os::unix::io::AsRawFd + Unpin,
{
    std::future::poll_fn(
        |cx: &mut Context<'_>| -> Poll<Option<(usize, Result<Vec<OwnedPacket>>)>> {
            let n = streams.len();
            if n == 0 {
                return Poll::Ready(None);
            }
            let start = *anchor % n;
            let mut all_done = true;
            for offset in 0..n {
                let i = (start + offset) % n;
                match Pin::new(&mut streams[i]).poll_next(cx) {
                    Poll::Ready(Some(item)) => {
                        *anchor = (i + 1) % n;
                        return Poll::Ready(Some((i, item)));
                    }
                    Poll::Ready(None) => {
                        // This stream is exhausted; keep checking the
                        // others. `all_done` stays true only if every
                        // stream reports Ready(None).
                    }
                    Poll::Pending => {
                        all_done = false;
                    }
                }
            }
            if all_done {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        },
    )
    .await
}

/// Tracks both a packet-batch deadline and an OS shutdown signal.
struct ShutdownSignal {
    stop: StopCondition,
    sig_int: Option<tokio::signal::unix::Signal>,
    sig_term: Option<tokio::signal::unix::Signal>,
}

impl ShutdownSignal {
    fn new(stop: StopCondition) -> Self {
        let (sig_int, sig_term) = match &stop {
            StopCondition::Signal => {
                let sigint =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
                let sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
                (sigint, sigterm)
            }
            StopCondition::Deadline(_) => (None, None),
        };
        Self {
            stop,
            sig_int,
            sig_term,
        }
    }

    async fn recv(&mut self) {
        match &mut self.stop {
            StopCondition::Deadline(t) => {
                tokio::time::sleep_until((*t).into()).await;
            }
            StopCondition::Signal => match (self.sig_int.as_mut(), self.sig_term.as_mut()) {
                (Some(i), Some(t)) => {
                    tokio::select! {
                        _ = i.recv() => {},
                        _ = t.recv() => {},
                    }
                }
                (Some(i), None) => {
                    let _ = i.recv().await;
                }
                (None, Some(t)) => {
                    let _ = t.recv().await;
                }
                // Couldn't install handlers — fall back to never-firing
                // (the user can still abort with the runtime exiting).
                (None, None) => std::future::pending::<()>().await,
            },
        }
    }
}

/// Async sibling of [`dispatch_lifecycle`]. Translates each
/// flowscope lifecycle event into its typed `FlowStarted<P>` /
/// `FlowEnded<P>` / `FlowEstablished<P>` / `AnyFlowAnomaly`
/// payload and dispatches through the async handler chain.
///
/// Cheap when no async handlers are registered:
/// [`Dispatcher::dispatch_async`] returns immediately if the
/// payload TypeId has no async slot. No allocation in that case.
async fn dispatch_lifecycle_async(
    dispatcher: &mut Dispatcher,
    evt: FsEvent<FlowKey>,
) -> Result<()> {
    match evt {
        FsEvent::FlowStarted { key, ts, l4 } => match l4 {
            Some(L4Proto::Tcp) => {
                dispatcher
                    .dispatch_async(&FlowStarted::<Tcp>::new(key, l4, ts))
                    .await?;
            }
            Some(L4Proto::Udp) => {
                dispatcher
                    .dispatch_async(&FlowStarted::<Udp>::new(key, l4, ts))
                    .await?;
            }
            #[cfg(feature = "icmp")]
            Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => {
                dispatcher
                    .dispatch_async(&FlowStarted::<Icmp>::new(key, l4, ts))
                    .await?;
            }
            _ => {}
        },
        FsEvent::FlowEnded {
            key,
            reason,
            stats,
            ts,
            l4,
            ..
        } => match l4 {
            Some(L4Proto::Tcp) => {
                dispatcher
                    .dispatch_async(&FlowEnded::<Tcp>::new(key, reason, stats, l4, ts))
                    .await?;
            }
            Some(L4Proto::Udp) => {
                dispatcher
                    .dispatch_async(&FlowEnded::<Udp>::new(key, reason, stats, l4, ts))
                    .await?;
            }
            #[cfg(feature = "icmp")]
            Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => {
                dispatcher
                    .dispatch_async(&FlowEnded::<Icmp>::new(key, reason, stats, l4, ts))
                    .await?;
            }
            _ => {}
        },
        FsEvent::FlowEstablished { key, ts, l4 } => {
            if matches!(l4, Some(L4Proto::Tcp)) {
                dispatcher
                    .dispatch_async(&FlowEstablished::<Tcp>::new(key, ts))
                    .await?;
            }
        }
        FsEvent::FlowAnomaly { key, kind, ts } => {
            dispatcher
                .dispatch_async(&AnyFlowAnomaly {
                    key: Some(key),
                    kind,
                    ts,
                })
                .await?;
        }
        FsEvent::TrackerAnomaly { kind, ts } => {
            dispatcher
                .dispatch_async(&AnyFlowAnomaly {
                    key: None,
                    kind,
                    ts,
                })
                .await?;
        }
        _ => {}
    }
    Ok(())
}

fn dispatch_lifecycle(
    dispatcher: &mut Dispatcher,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    evt: FsEvent<FlowKey>,
    source: SourceIdx,
) -> Result<()> {
    // Macro inlines the Ctx construction at each match arm so the
    // borrow checker can shorten each `&mut` borrow to the
    // dispatch call. Hoisting it into a closure trips
    // higher-rank-lifetime inference.
    macro_rules! dispatch_one {
        ($ty:ty, $payload:expr, $flow:expr, $ts:expr) => {{
            let mut ctx = Ctx {
                flow: $flow,
                ts: $ts,
                source,
                state_map: &mut *state_map,
                sink: &mut *sink,
                counters: &mut *counters,
            };
            dispatcher.dispatch::<$ty>(&$payload, &mut ctx)?;
        }};
    }

    match evt {
        FsEvent::FlowStarted { key, ts, l4 } => match l4 {
            Some(L4Proto::Tcp) => {
                dispatch_one!(
                    FlowStarted<Tcp>,
                    FlowStarted::<Tcp>::new(key, l4, ts),
                    Some(key),
                    ts
                );
            }
            Some(L4Proto::Udp) => {
                dispatch_one!(
                    FlowStarted<Udp>,
                    FlowStarted::<Udp>::new(key, l4, ts),
                    Some(key),
                    ts
                );
            }
            #[cfg(feature = "icmp")]
            Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => {
                dispatch_one!(
                    FlowStarted<Icmp>,
                    FlowStarted::<Icmp>::new(key, l4, ts),
                    Some(key),
                    ts
                );
            }
            _ => {}
        },
        FsEvent::FlowEnded {
            key,
            reason,
            stats,
            ts,
            l4,
            ..
        } => match l4 {
            Some(L4Proto::Tcp) => {
                dispatch_one!(
                    FlowEnded<Tcp>,
                    FlowEnded::<Tcp>::new(key, reason, stats, l4, ts),
                    Some(key),
                    ts
                );
            }
            Some(L4Proto::Udp) => {
                dispatch_one!(
                    FlowEnded<Udp>,
                    FlowEnded::<Udp>::new(key, reason, stats, l4, ts),
                    Some(key),
                    ts
                );
            }
            #[cfg(feature = "icmp")]
            Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => {
                dispatch_one!(
                    FlowEnded<Icmp>,
                    FlowEnded::<Icmp>::new(key, reason, stats, l4, ts),
                    Some(key),
                    ts
                );
            }
            _ => {}
        },
        FsEvent::FlowEstablished { key, ts, l4 } => {
            if matches!(l4, Some(L4Proto::Tcp)) {
                dispatch_one!(
                    FlowEstablished<Tcp>,
                    FlowEstablished::<Tcp>::new(key, ts),
                    Some(key),
                    ts
                );
            }
        }
        FsEvent::FlowAnomaly { key, kind, ts } => {
            dispatch_one!(
                AnyFlowAnomaly,
                AnyFlowAnomaly {
                    key: Some(key),
                    kind,
                    ts,
                },
                Some(key),
                ts
            );
        }
        FsEvent::TrackerAnomaly { kind, ts } => {
            dispatch_one!(
                AnyFlowAnomaly,
                AnyFlowAnomaly {
                    key: None,
                    kind,
                    ts,
                },
                None,
                ts
            );
        }
        // FlowPacket / FlowTick / ParserClosed not surfaced in Phase B.
        _ => {}
    }
    Ok(())
}
