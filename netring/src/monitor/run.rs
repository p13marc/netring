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
use std::time::{Duration, Instant};

use flowscope::L4Proto;
use flowscope::driver::Event as FsEvent;
use flowscope::extract::FiveTuple;
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
use crate::protocol::event_typed::{
    AnyFlowAnomaly, FlowEnded, FlowEstablished, FlowPacket, FlowStarted, FlowTick, ParserClosed,
    Tick,
};
use std::time::SystemTime;

/// How long to keep the run loop alive.
pub(crate) enum StopCondition {
    /// Stop when wall-clock reaches this deadline.
    Deadline(Instant),
    /// Stop on Ctrl-C / SIGTERM. Available only when the tokio
    /// `signal` feature is on; today that's transitively enabled
    /// by netring's `tokio` feature.
    Signal,
    /// 0.21 E.2: stop after `window` of inactivity. The run loop
    /// resets a deadline each time a packet batch arrives; if the
    /// deadline expires before the next batch, the loop exits.
    /// Useful for pcap replay (auto-stop after EOF + grace) and
    /// one-shot scans where the upstream traffic stops cleanly.
    Idle(Duration),
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
        monitor_name,
        drain_timeout,
        broadcast_handles: _,
    } = monitor;
    // Borrow the monitor name as `&str` for the run loop's
    // dispatch sites. The owned `Box<str>` lives in this stack
    // frame so the borrow is valid for the run loop's lifetime.
    let monitor_name_borrow: Option<&str> = monitor_name.as_deref();

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
    // 0.21 E.2: bumped on every packet batch + every tick. Idle
    // mode computes its deadline as `last_event_at + window`,
    // so refreshing this resets the idle timer. Initialized to
    // "now" so the loop has the full window of grace before the
    // first event arrives.
    let mut last_event_at = Instant::now();

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
            _ = shutdown.recv(last_event_at) => break,
            packet = next_packet(&mut streams, &mut rr_anchor) => packet,
            tick_idx = next_tick(&mut tick_intervals), if !tick_intervals.is_empty() => {
                // Reset idle timer on every tick — periodic
                // tick fires are intended user activity, not
                // dead air. Without this, a 1s idle timeout +
                // 500ms tick handler would never resolve.
                last_event_at = Instant::now();
                fire_tick(
                    tick_idx,
                    &mut tick_handlers,
                    &mut dispatcher,
                    sink.as_mut(),
                    &mut state_map,
                    &mut counters,
                    monitor_name_borrow,
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
        // Reset idle timer on every received batch.
        last_event_at = Instant::now();

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
                    monitor_name_borrow,
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
                // 0.21 D.4: stamp the monitor name on this ctx so
                // typed-message handlers see it too. `Ctx::new`
                // defaults `monitor_name` to `None`; set it
                // explicitly after construction.
                ctx.monitor_name = monitor_name_borrow;
                slot.drain_and_dispatch(&mut dispatcher, &mut ctx)?;
            }
        }
    }

    // 0.21 D.2: graceful drain phase. After the stop condition
    // fires, flush in-flight flows out of the central tracker,
    // drain each protocol slot's queued messages, and flush the
    // sink. Skipped entirely when `drain_timeout` is zero — useful
    // for fail-fast smoke tests that don't care about residual
    // events.
    if !drain_timeout.is_zero() {
        let deadline = Instant::now() + drain_timeout;
        drain_phase(
            &mut driver,
            &mut dispatcher,
            sink.as_mut(),
            &mut state_map,
            &mut counters,
            &mut protocol_slots,
            monitor_name_borrow,
            deadline,
        )
        .await?;
    }

    Ok(())
}

/// 0.21 D.2: drain residual events after the run loop's stop
/// condition fires.
///
/// Steps, each guarded by the `deadline`:
///
/// 1. `driver.finish()` — flush in-flight flows out of the central
///    tracker (synthesizes `FlowEnded` events for anything still
///    alive). Dispatches each through the same lifecycle path the
///    run loop uses, so handlers see end-of-stream events the
///    same way they see live ones.
/// 2. For each protocol slot, drain queued typed messages.
/// 3. `sink.flush()` — give a chance for buffered writes (eve-sink,
///    json sink, etc.) to land on disk.
///
/// Best-effort: a slow handler can push past `deadline`. The
/// deadline check sits between steps, not inside them. If
/// step 1 already overran, steps 2 and 3 are skipped to bound
/// total shutdown time.
#[allow(clippy::too_many_arguments)]
async fn drain_phase(
    driver: &mut flowscope::driver::Driver<FiveTuple>,
    dispatcher: &mut Dispatcher,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    protocol_slots: &mut [Box<dyn crate::monitor::ProtocolSlot>],
    monitor_name: Option<&str>,
    deadline: Instant,
) -> Result<()> {
    // Step 1: drain the central tracker.
    let mut leftover: Vec<FsEvent<FlowKey>> = Vec::new();
    driver.finish_into(&mut leftover);
    for evt in leftover.drain(..) {
        if Instant::now() >= deadline {
            return Ok(());
        }
        dispatch_lifecycle(
            dispatcher,
            sink,
            state_map,
            counters,
            evt.clone(),
            SourceIdx(0),
            monitor_name,
        )?;
        dispatch_lifecycle_async(dispatcher, evt).await?;
    }

    if Instant::now() >= deadline {
        return Ok(());
    }

    // Step 2: drain each protocol slot's typed messages.
    let ts = flowscope::Timestamp::from_system_time(SystemTime::now());
    for slot in protocol_slots.iter_mut() {
        if Instant::now() >= deadline {
            return Ok(());
        }
        let mut ctx = Ctx::new(None, ts, SourceIdx(0), state_map, sink, counters);
        ctx.monitor_name = monitor_name;
        slot.drain_and_dispatch(dispatcher, &mut ctx)?;
    }

    if Instant::now() >= deadline {
        return Ok(());
    }

    // Step 3: flush the sink. The `AnomalySink::flush` default is
    // `Ok(())`; impls that buffer (eve-sink, json sink) actually
    // do work here. Errors propagate as `io::Error`; the cast
    // through netring's `Error` wraps them.
    sink.flush().map_err(|e| {
        crate::error::Error::Io(std::io::Error::new(e.kind(), format!("sink flush: {e}")))
    })?;

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
    monitor_name: Option<&str>,
) -> Result<()> {
    let reg = &mut tick_handlers[tick_idx];
    let tick = Tick {
        now: flowscope::Timestamp::from_system_time(SystemTime::now()),
        period: reg.period,
    };
    {
        let mut ctx = Ctx::new(None, tick.now, SourceIdx(0), state_map, sink, counters);
        ctx.monitor_name = monitor_name;
        (reg.handler)(&tick, &mut ctx)?;
    }
    {
        let mut ctx = Ctx::new(None, tick.now, SourceIdx(0), state_map, sink, counters);
        ctx.monitor_name = monitor_name;
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
            StopCondition::Deadline(_) | StopCondition::Idle(_) => (None, None),
        };
        Self {
            stop,
            sig_int,
            sig_term,
        }
    }

    /// 0.21 E.2: `last_event_at` parameterizes the idle-window
    /// deadline. For `Deadline` / `Signal` it's ignored.
    async fn recv(&mut self, last_event_at: Instant) {
        match &mut self.stop {
            StopCondition::Deadline(t) => {
                tokio::time::sleep_until((*t).into()).await;
            }
            StopCondition::Idle(window) => {
                tokio::time::sleep_until((last_event_at + *window).into()).await;
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
        FsEvent::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
        } => match key.proto {
            L4Proto::Tcp => {
                dispatcher
                    .dispatch_async(&FlowPacket::<Tcp>::new(key, side, len, tcp, ts))
                    .await?;
            }
            L4Proto::Udp => {
                dispatcher
                    .dispatch_async(&FlowPacket::<Udp>::new(key, side, len, tcp, ts))
                    .await?;
            }
            #[cfg(feature = "icmp")]
            L4Proto::Icmp | L4Proto::IcmpV6 => {
                dispatcher
                    .dispatch_async(&FlowPacket::<Icmp>::new(key, side, len, tcp, ts))
                    .await?;
            }
            _ => {}
        },
        FsEvent::FlowTick { key, stats, ts } => match key.proto {
            L4Proto::Tcp => {
                dispatcher
                    .dispatch_async(&FlowTick::<Tcp>::new(key, stats, ts))
                    .await?;
            }
            L4Proto::Udp => {
                dispatcher
                    .dispatch_async(&FlowTick::<Udp>::new(key, stats, ts))
                    .await?;
            }
            #[cfg(feature = "icmp")]
            L4Proto::Icmp | L4Proto::IcmpV6 => {
                dispatcher
                    .dispatch_async(&FlowTick::<Icmp>::new(key, stats, ts))
                    .await?;
            }
            _ => {}
        },
        FsEvent::ParserClosed {
            key,
            parser_kind,
            reason,
            ts,
        } => match key.proto {
            L4Proto::Tcp => {
                dispatcher
                    .dispatch_async(&ParserClosed::<Tcp>::new(key, parser_kind, reason, ts))
                    .await?;
            }
            L4Proto::Udp => {
                dispatcher
                    .dispatch_async(&ParserClosed::<Udp>::new(key, parser_kind, reason, ts))
                    .await?;
            }
            #[cfg(feature = "icmp")]
            L4Proto::Icmp | L4Proto::IcmpV6 => {
                dispatcher
                    .dispatch_async(&ParserClosed::<Icmp>::new(key, parser_kind, reason, ts))
                    .await?;
            }
            _ => {}
        },
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
    monitor_name: Option<&str>,
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
                monitor_name,
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
        FsEvent::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
        } => match key.proto {
            L4Proto::Tcp => {
                dispatch_one!(
                    FlowPacket<Tcp>,
                    FlowPacket::<Tcp>::new(key, side, len, tcp, ts),
                    Some(key),
                    ts
                );
            }
            L4Proto::Udp => {
                dispatch_one!(
                    FlowPacket<Udp>,
                    FlowPacket::<Udp>::new(key, side, len, tcp, ts),
                    Some(key),
                    ts
                );
            }
            #[cfg(feature = "icmp")]
            L4Proto::Icmp | L4Proto::IcmpV6 => {
                dispatch_one!(
                    FlowPacket<Icmp>,
                    FlowPacket::<Icmp>::new(key, side, len, tcp, ts),
                    Some(key),
                    ts
                );
            }
            _ => {}
        },
        FsEvent::FlowTick { key, stats, ts } => match key.proto {
            L4Proto::Tcp => {
                dispatch_one!(
                    FlowTick<Tcp>,
                    FlowTick::<Tcp>::new(key, stats, ts),
                    Some(key),
                    ts
                );
            }
            L4Proto::Udp => {
                dispatch_one!(
                    FlowTick<Udp>,
                    FlowTick::<Udp>::new(key, stats, ts),
                    Some(key),
                    ts
                );
            }
            #[cfg(feature = "icmp")]
            L4Proto::Icmp | L4Proto::IcmpV6 => {
                dispatch_one!(
                    FlowTick<Icmp>,
                    FlowTick::<Icmp>::new(key, stats, ts),
                    Some(key),
                    ts
                );
            }
            _ => {}
        },
        FsEvent::ParserClosed {
            key,
            parser_kind,
            reason,
            ts,
        } => match key.proto {
            L4Proto::Tcp => {
                dispatch_one!(
                    ParserClosed<Tcp>,
                    ParserClosed::<Tcp>::new(key, parser_kind, reason, ts),
                    Some(key),
                    ts
                );
            }
            L4Proto::Udp => {
                dispatch_one!(
                    ParserClosed<Udp>,
                    ParserClosed::<Udp>::new(key, parser_kind, reason, ts),
                    Some(key),
                    ts
                );
            }
            #[cfg(feature = "icmp")]
            L4Proto::Icmp | L4Proto::IcmpV6 => {
                dispatch_one!(
                    ParserClosed<Icmp>,
                    ParserClosed::<Icmp>::new(key, parser_kind, reason, ts),
                    Some(key),
                    ts
                );
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}
