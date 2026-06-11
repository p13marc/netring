//! Run loop for the 0.20 [`Monitor`].
//!
//! Phase F.1 added multi-interface fan-in (N [`AsyncCapture`]s
//! round-robin'd into one driver+dispatcher); F.2 added the
//! tick handler firing path. F.3 (per-CPU sharding) lives
//! separately and isn't reached from this run loop. Each
//! iteration:
//!
//! 1. await *either* the next packet batch (across all N
//!    interfaces, fair-round-robin) *or* the next tick from any
//!    registered tick handler,
//! 2. on packet: feed it to the flowscope driver and translate
//!    the resulting lifecycle events into typed `FlowStarted<P>`
//!    / `FlowEnded<P>` / `FlowEstablished<P>` / `AnyFlowAnomaly`
//!    payloads dispatched through the handler table — with
//!    `ctx.source` set to the interface's SourceIdx,
//! 3. on packet: drain each protocol-slot's typed parser
//!    messages and dispatch them,
//! 4. on tick: invoke the registered `.tick(period, handler)`
//!    closure *and* dispatch the typed `Tick` event so users
//!    who registered via `.on::<Tick>(...)` see it too.

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
use crate::protocol::event_typed::{AnyFlowAnomaly, FlowEnded, FlowEstablished, FlowStarted, Tick};
use std::time::SystemTime;

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
        mut tick_handlers,
        detector_names: _,
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

    // Phase F.2: one tokio interval per registered tick handler.
    // First tick fires after `period` (interval_at with deadline =
    // now + period), not immediately. `Skip` missed-tick behaviour
    // so a slow tick handler doesn't pile up backlog ticks.
    let mut tick_intervals: Vec<tokio::time::Interval> = tick_handlers
        .iter()
        .map(|t| {
            let mut int =
                tokio::time::interval_at(tokio::time::Instant::now() + t.period, t.period);
            int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            int
        })
        .collect();

    loop {
        // tokio::select! waits on shutdown, the next packet, OR
        // the next tick. The `if !tick_intervals.is_empty()`
        // gate keeps the tick branch from being polled when no
        // handlers are registered (saves one cx wake per loop).
        let next = tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            packet = next_packet(&mut streams, &mut rr_anchor) => packet,
            tick_idx = next_tick(&mut tick_intervals), if !tick_intervals.is_empty() => {
                fire_tick(
                    tick_idx,
                    &mut tick_handlers,
                    &mut dispatcher,
                    sink.as_mut(),
                    &mut state_map,
                    &mut counters,
                )
                .await?;
                continue;
            }
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

/// Round-robin poll across N tick intervals. Returns the index of
/// whichever interval ticked first.
///
/// Symmetric to [`next_packet`] — the same fairness story applies,
/// just without an `anchor` because interval ticks are
/// time-driven, not rate-driven (the slowest interval can't
/// starve the fastest one even with naive ordering). We still
/// scan from index 0 every poll; the win from an anchor is
/// negligible for tick handlers.
async fn next_tick(intervals: &mut [tokio::time::Interval]) -> usize {
    std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<usize> {
        for (i, interval) in intervals.iter_mut().enumerate() {
            if interval.poll_tick(cx).is_ready() {
                return Poll::Ready(i);
            }
        }
        Poll::Pending
    })
    .await
}

/// Fire the tick handler at `tick_idx`.
///
/// Two paths fire on every tick:
///
/// 1. The `.tick(period, handler)` registration's boxed closure —
///    drives the period scheduling and is the ergonomic
///    registration form.
/// 2. The dispatcher's typed `Tick` slot (sync + async) — so
///    users who registered via `.on::<Tick>(...)` also receive
///    the event.
///
/// Both run in the order: closure first, then dispatcher.
async fn fire_tick(
    tick_idx: usize,
    tick_handlers: &mut [crate::monitor::tick::TickRegistration],
    dispatcher: &mut Dispatcher,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
) -> Result<()> {
    let reg = &mut tick_handlers[tick_idx];
    let tick = Tick {
        now: flowscope::Timestamp::from_system_time(SystemTime::now()),
        period: reg.period,
    };
    {
        let mut ctx = Ctx::new(None, tick.now, SourceIdx(0), state_map, sink, counters);
        (reg.handler)(&tick, &mut ctx)?;
    }
    {
        let mut ctx = Ctx::new(None, tick.now, SourceIdx(0), state_map, sink, counters);
        dispatcher.dispatch::<Tick>(&tick, &mut ctx)?;
    }
    dispatcher.dispatch_async::<Tick>(&tick).await?;
    Ok(())
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
