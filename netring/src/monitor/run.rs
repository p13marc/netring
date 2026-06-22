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

use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use flowscope::L4Proto;
use flowscope::PacketView;
use flowscope::driver::Event as FsEvent;
use flowscope::extract::FiveTuple;

use crate::AsyncCapture;
use crate::anomaly::sink::AnomalySink;
use crate::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
use crate::error::Result;
use crate::monitor::backend::AnyBackend;
use crate::monitor::dispatcher::Dispatcher;
use crate::monitor::subscription::PacketSubscription;
use crate::monitor::subscription::packet::{PacketFields, packet_field_extractor};
use crate::monitor::{BackendErrorPolicy, HandlerErrorPolicy, Monitor};
use crate::protocol::FlowKey;
#[cfg(feature = "icmp")]
use crate::protocol::builtin::Icmp;
use crate::protocol::builtin::{Tcp, Udp};
use crate::protocol::event_typed::{
    AnyFlowAnomaly, FlowEnded, FlowEstablished, FlowPacket, FlowStarted, FlowTick, ParserClosed,
    TcpRst, Tick,
};
use std::time::SystemTime;

/// Issue #23: a borrow of the ARP detector's learned `IP → MAC` table, threaded
/// into the post-borrow dispatchers so flow/session/lifecycle handlers can read
/// it via [`Ctx::arp_table`](crate::ctx::Ctx::arp_table). `None` when no ARP
/// hook is armed (or the `arp` feature is off). The type is the unconditional
/// `NeighborTable` so the dispatch signatures stay feature-agnostic.
type ArpTableRef<'a> =
    Option<&'a flowscope::correlate::NeighborTable<std::net::Ipv4Addr, flowscope::MacAddr>>;

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

/// 0.25 W1e: how to (re)open a capture backend, kept parallel to the run loop's
/// `caps` so `BackendErrorPolicy::Reopen` can rebuild a failed source with the
/// same kind + filter as the original.
enum BackendSpec {
    /// AF_PACKET on the named interface.
    AfPacket(String),
    /// AF_XDP per its interface spec (bare vs self-loaded program).
    #[cfg(feature = "af-xdp")]
    Xdp(crate::monitor::XdpIfaceSpec),
    /// Issue #6 M5: a pre-built AF_XDP socket injected by `XdpShardedRunner`.
    /// Placeholder so `specs` stays parallel to `caps`; the actual socket comes
    /// from the Monitor's `injected_xdp` vec at first open. Not reopenable.
    #[cfg(feature = "af-xdp")]
    XdpProvided,
}

/// Open (or re-open) one capture backend from its [`BackendSpec`], applying the
/// shared fanout group + kernel prefilter for AF_PACKET. Used both for the
/// initial open and for `BackendErrorPolicy::Reopen`.
fn open_backend(
    spec: &BackendSpec,
    fanout: Option<(crate::config::FanoutMode, u16)>,
    kernel_prefilter: &Option<crate::config::BpfFilter>,
    promiscuous: bool,
) -> Result<AnyBackend> {
    match spec {
        // 0.21 C: with a fanout set (single-shard or ShardedRunner) open the
        // ring in the configured fanout group; otherwise plain open. Either way
        // the AF_PACKET ring honors the monitor-wide promiscuous flag (issue #4).
        BackendSpec::AfPacket(iface) => {
            let mut builder = crate::Capture::builder()
                .interface(iface)
                .promiscuous(promiscuous);
            if let Some((mode, group_id)) = fanout {
                builder = builder.fanout(mode, group_id);
            }
            let cap = AsyncCapture::new(builder.build()?)?;
            // 0.25 S2: push the conservative fail-open kernel prefilter (union of
            // every consumer's interest) into the socket — a superset, so it only
            // sheds traffic nobody needs.
            if let Some(filter) = kernel_prefilter {
                cap.set_filter(filter)?;
            }
            Ok(AnyBackend::AfPacket(cap))
        }
        #[cfg(feature = "af-xdp")]
        BackendSpec::Xdp(xspec) => open_xdp_backend(xspec, promiscuous),
        // Reached only on Reopen — first open takes the socket from the
        // Monitor's `injected_xdp` vec. An injected backend can't be rebuilt.
        #[cfg(feature = "af-xdp")]
        BackendSpec::XdpProvided => Err(crate::error::Error::Config(
            "cannot reopen an injected AF_XDP backend (XdpShardedRunner): the \
             program and socket registration live outside the Monitor"
                .into(),
        )),
    }
}

/// Open the AF_XDP backend for one capture interface (0.25 W1a; multi-queue #6).
///
/// A bare spec (`self_load = false`) opens a plain socket and relies on an
/// externally-attached redirect program. A self-loading spec (requires
/// `xdp-loader`) builds through [`crate::XdpSocketBuilder`] / [`crate::xdp::XdpCapture`]
/// with the built-in redirect-all program attached in `SKB_MODE`:
/// - `queues == Single(0)` (the default) → one socket on queue 0 → `AnyBackend::Xdp`;
/// - any other `Queues` (e.g. `Auto`) → one socket per RX queue behind a single
///   program, drained round-robin → `AnyBackend::XdpMq` (issue #6 Tier 1, removes
///   the silent single-queue under-capture footgun).
///
/// `promiscuous` is the monitor-wide flag ([`MonitorBuilder::promiscuous`], #4).
#[cfg(feature = "af-xdp")]
fn open_xdp_backend(spec: &crate::monitor::XdpIfaceSpec, promiscuous: bool) -> Result<AnyBackend> {
    #[cfg(feature = "xdp-loader")]
    if spec.self_load {
        // Multi-queue: anything but the default single queue 0 opens one socket
        // per queue behind one program (issue #6).
        if !matches!(spec.queues, crate::xdp::Queues::Single(0)) {
            let capture = crate::xdp::XdpCapture::builder()
                .interface(&spec.iface)
                .queues(spec.queues.clone())
                .promiscuous(promiscuous)
                .build()?;
            return Ok(AnyBackend::XdpMq(crate::AsyncXdpCapture::new(capture)?));
        }
        let socket = crate::XdpSocketBuilder::default()
            .interface(&spec.iface)
            .mode(crate::XdpMode::Rx)
            .promiscuous(promiscuous)
            .with_default_program()
            .build()?;
        return Ok(AnyBackend::Xdp(crate::AsyncXdpSocket::new(socket)?));
    }
    // Bare path (externally-attached redirect program). `queues` is ignored —
    // the external program owns the redirect map, so we can't register N sockets
    // on it. Build through the builder so promiscuous mode can be applied.
    let socket = crate::XdpSocketBuilder::default()
        .interface(&spec.iface)
        .promiscuous(promiscuous)
        .build()?;
    Ok(AnyBackend::Xdp(crate::AsyncXdpSocket::new(socket)?))
}

pub(crate) async fn run_loop(monitor: Monitor, stop: StopCondition) -> Result<()> {
    let Monitor {
        interfaces,
        #[cfg(feature = "af-xdp")]
        xdp_interfaces,
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
        #[cfg(all(feature = "pcap", feature = "tokio"))]
            pcap_source_path: _,
        #[cfg(all(feature = "pcap", feature = "tokio"))]
            pcap_speed_factor: _,
        mut flow_states,
        fanout,
        label_table,
        mut merge_rx,
        handler_error_policy,
        backend_error_policy,
        mut capture_stats,
        health,
        mut flow_exporters,
        flow_active_timeout,
        packet_subs,
        kernel_prefilter,
        promiscuous,
        #[cfg(feature = "af-xdp")]
        xdp_queues,
        #[cfg(feature = "af-xdp")]
        injected_xdp,
        #[cfg(feature = "arp")]
        mut arp_watch,
        #[cfg(feature = "ndp")]
        mut ndp_watch,
        #[cfg(feature = "lldp")]
        mut lldp_watch,
        #[cfg(feature = "cdp")]
        mut cdp_watch,
        #[cfg(feature = "asset")]
        mut asset_watch,
    } = monitor;
    // Borrow the monitor name as `&str` for the run loop's
    // dispatch sites. The owned `Box<str>` lives in this stack
    // frame so the borrow is valid for the run loop's lifetime.
    let monitor_name_borrow: Option<&str> = monitor_name.as_deref();

    // 0.25 A1: directional extractor for packet-tier field evaluation (a=src,
    // b=dst). Stateless; only consulted per frame when packet subs exist.
    let pkt_extractor = packet_field_extractor();

    // Phase F.1: open one AsyncCapture per interface. The order
    // matches the builder's `.interfaces([...])` order; each event
    // gets the corresponding `SourceIdx`. A single-interface
    // monitor (the common case) opens exactly one ring — the
    // round-robin select reduces to a one-armed select with the
    // same latency as the prior single-cap path.
    // 0.24 Phase B: each capture source is an `AnyBackend` (AF_PACKET today,
    // AF_XDP behind `af-xdp`), drained through one backend-agnostic path. The
    // run loop holds the backend directly (not an owned `PacketStream`) so it
    // can drain **borrowed** zero-copy batches in place — no per-packet
    // `to_owned` copy. The future stays `Send` because the only borrow held
    // across an `.await` lives inside `drain_batch`, and `AnyBackend` is
    // `Send`; all dispatch runs *after* the batch is dropped.
    // 0.25 W1e: record how to (re)open each backend so
    // `BackendErrorPolicy::Reopen` can rebuild a failed source in place. Built
    // in the exact order the run loop indexes `caps`: AF_PACKET interfaces
    // first, then AF_XDP (matching the prior two-loop open order).
    let mut specs: Vec<BackendSpec> = Vec::new();
    for iface in &interfaces {
        specs.push(BackendSpec::AfPacket(iface.clone()));
    }
    #[cfg(feature = "af-xdp")]
    for spec in &xdp_interfaces {
        // Stamp the monitor-wide queue selection (issue #6) onto each spec.
        let mut spec = spec.clone();
        spec.queues = xdp_queues.clone();
        specs.push(BackendSpec::Xdp(spec));
    }
    // Issue #6 M5: one placeholder spec per injected (pre-built) AF_XDP socket,
    // keeping `specs` parallel to `caps`. The sockets are consumed below.
    #[cfg(feature = "af-xdp")]
    let mut injected_iter = injected_xdp.into_iter();
    #[cfg(feature = "af-xdp")]
    for _ in 0..injected_iter.len() {
        specs.push(BackendSpec::XdpProvided);
    }

    let mut caps: Vec<AnyBackend> = Vec::with_capacity(specs.len());
    for spec in &specs {
        let cap = match spec {
            #[cfg(feature = "af-xdp")]
            BackendSpec::XdpProvided => AnyBackend::Xdp(
                injected_iter
                    .next()
                    .expect("one injected socket per XdpProvided spec"),
            ),
            _ => open_backend(spec, fanout, &kernel_prefilter, promiscuous)?,
        };
        caps.push(cap);
    }
    // 0.24 Phase C4: all sockets are open and the loop is about to run —
    // readiness flips true. `mark_started` stamps the uptime/liveness
    // clock now (not at build time).
    health.mark_started();
    health.mark_sockets_open();

    let mut events: Vec<FsEvent<FlowKey>> = Vec::with_capacity(64);
    let mut shutdown = ShutdownSignal::new(stop);
    let mut rr_anchor: usize = 0;
    // 0.24 Phase B: consecutive backend-error count for the SkipSource circuit
    // breaker. Reset on every successful readable wake.
    let mut backend_errors: u64 = 0;
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

    // 0.24 Phase C: capture-telemetry sampling. Only armed when an
    // `on_capture_stats` handler is registered — otherwise the `Option`
    // is `None` and the `select!` branch is gated off at zero cost (same
    // pattern as the tick / merge branches). The sampler keeps per-source
    // cumulative state so each sample's `drop_rate` is windowed.
    let mut telemetry_interval = capture_stats.as_ref().map(|reg| {
        let mut int =
            tokio::time::interval_at(tokio::time::Instant::now() + reg.period, reg.period);
        int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        int
    });
    // Allocate per-source sampler slots only when telemetry is armed — an
    // empty `Vec` doesn't allocate, so an unconfigured monitor pays nothing.
    let mut telemetry_sampler =
        crate::monitor::telemetry::TelemetrySampler::new(if capture_stats.is_some() {
            caps.len()
        } else {
            0
        });

    // 0.25 W1c: active-timeout flow export. Armed only when a period is set AND
    // at least one exporter is registered — otherwise the `Option` is `None`
    // and the `select!` branch is gated off at zero cost (same pattern as the
    // tick / telemetry branches). `last_active_export` dedups per flow so a
    // long-lived flow gets one interim record per active-timeout window.
    let mut active_export = flow_active_timeout
        .filter(|_| !flow_exporters.is_empty())
        .map(|period| {
            let mut int = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            (int, period)
        });
    let mut last_active_export: std::collections::HashMap<FlowKey, flowscope::Timestamp> =
        std::collections::HashMap::new();

    loop {
        // tokio::select! waits on shutdown, the next packet, OR
        // the next tick. The `if !tick_intervals.is_empty()`
        // gate keeps the tick branch from being polled when no
        // handlers are registered (saves one cx wake per loop).
        let ready = tokio::select! {
            biased;
            _ = shutdown.recv(last_event_at) => break,
            idx = ready_capture(&mut caps, &mut rr_anchor) => idx,
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
                    &mut flow_states,
                    &label_table,
                )
                .await?;
                // 0.24 Phase C4: a tick is progress too — keeps liveness
                // alive on a quiet link with a registered heartbeat tick.
                health.record_event(driver.tracker().flow_count());
                continue;
            }
            // 0.22 §5.1: cross-shard merge probe. Gated so non-merged
            // monitors never poll it (zero cost, like the tick branch).
            // Out-of-band — doesn't touch the idle timer.
            req = recv_merge(&mut merge_rx), if merge_rx.is_some() => {
                if let Some(req) = req {
                    let taken = state_map.take_dyn(req.type_id);
                    let _ = req.reply.send(taken);
                }
                continue;
            }
            // 0.24 Phase C: capture-telemetry sample. Gated on the
            // `on_capture_stats` registration so monitors without it
            // never poll the interval. Out-of-band like the merge probe:
            // sampling is observability, not traffic, so it must NOT reset
            // the idle timer (else `on_capture_stats` + `run_until_idle`
            // would never idle-stop). The sampling itself runs in the
            // branch body — after the `select!` drops the other branch
            // futures, so the `&caps` read here can't alias the
            // `ready_capture` branch's `&mut caps`.
            _ = next_telemetry_sample(&mut telemetry_interval),
                if telemetry_interval.is_some() =>
            {
                if let Some(reg) = capture_stats.as_mut() {
                    sample_and_fire_capture_stats(
                        &caps,
                        &mut telemetry_sampler,
                        reg,
                        sink.as_mut(),
                        &mut state_map,
                        &mut counters,
                        monitor_name_borrow,
                        &mut flow_states,
                        &label_table,
                        &health,
                    )?;
                }
                continue;
            }
            // 0.25 W1c: active-timeout flow export. Out-of-band like telemetry —
            // emitting interim flow records is observability, not traffic, so it
            // must NOT reset the idle timer.
            _ = next_active_export(&mut active_export), if active_export.is_some() => {
                if let Some((_, period)) = active_export.as_ref() {
                    emit_active_flow_records(
                        &driver,
                        &mut flow_exporters,
                        &mut last_active_export,
                        *period,
                    );
                }
                continue;
            }
        };
        let i = match ready {
            Some((i, Ok(()))) => i,
            Some((i, Err(e))) => match backend_error_policy {
                BackendErrorPolicy::FailFast => return Err(e),
                BackendErrorPolicy::SkipSource => {
                    backend_errors += 1;
                    health.record_backend_error();
                    tracing::warn!(error = %e, count = backend_errors, "capture backend error (SkipSource)");
                    // Circuit breaker: a persistently-failing fd would otherwise
                    // spin the readiness select. Back off, and after many
                    // consecutive failures give up rather than burn a core.
                    if backend_errors > 64 {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                // 0.25 W1e: try to rebuild the failed source in place from its
                // recorded spec. A failed re-open leaves the (still-broken)
                // backend as-is so the next error retries it; same circuit
                // breaker as SkipSource bounds a hard-down source.
                BackendErrorPolicy::Reopen => {
                    backend_errors += 1;
                    health.record_backend_error();
                    match open_backend(&specs[i], fanout, &kernel_prefilter, promiscuous) {
                        Ok(b) => {
                            caps[i] = b;
                            tracing::warn!(error = %e, idx = i, count = backend_errors, "capture backend error (Reopen) — source reopened");
                        }
                        Err(e2) => {
                            tracing::warn!(error = %e, reopen_error = %e2, idx = i, count = backend_errors, "capture backend error (Reopen) — reopen failed, will retry");
                        }
                    }
                    if backend_errors > 64 {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            None => break, // all captures exhausted (AF_PACKET never reports this)
        };
        backend_errors = 0; // a successful wake clears the circuit breaker
        let source = SourceIdx(i as u8);
        // Reset idle timer on every readable wake.
        last_event_at = Instant::now();

        // IN-BORROW: drain every retired block now ready on this capture and
        // feed each packet's zero-copy view to the tracker. `track_into` copies
        // only the metadata it needs into the owned `events` buffer (and feeds
        // the L7 parsers, which buffer owned messages) — no packet-data copy.
        events.clear();
        // IN-BORROW: drain the ready batches on this backend, feeding each
        // packet's zero-copy view to the tracker. `drain_batch` holds the
        // ring/UMEM borrow only across this synchronous callback loop and
        // drops it before returning — no borrow crosses the dispatch
        // `.await` below, which is what keeps the run loop's future `Send`.
        // `track_into` copies only the metadata it needs into `events`; no
        // packet-data copy.
        // 0.25 A1: when packet-tier subs exist, dispatch them per frame
        // *inside* the synchronous drain (before `track_into`), so a borrowed
        // `PacketView` reaches the handler with no copy. The dispatch is
        // synchronous — its borrows drop before the `.await` below, preserving
        // `Send`. A `Propagate` error is stashed and surfaced after the drain.
        let mut packet_err: Option<crate::error::Error> = None;
        let last_ts = caps[i]
            .drain_batch(|view| {
                if !packet_subs.is_empty()
                    && packet_err.is_none()
                    && let Err(e) = dispatch_packet_subs(
                        &packet_subs,
                        view,
                        &pkt_extractor,
                        sink.as_mut(),
                        &mut state_map,
                        &mut counters,
                        &mut flow_states,
                        &label_table,
                        source,
                        monitor_name_borrow,
                        handler_error_policy,
                        &health,
                    )
                {
                    packet_err = Some(e);
                }
                // Issue #12: parse the L2 frame for ARP and drive the detector,
                // in-borrow like the packet subs (synchronous — its borrows
                // drop before the `.await`, preserving `Send`).
                #[cfg(feature = "arp")]
                if let Some(watch) = arp_watch.as_mut()
                    && packet_err.is_none()
                    && let Err(e) = dispatch_arp(
                        watch,
                        view,
                        sink.as_mut(),
                        &mut state_map,
                        &mut counters,
                        &mut flow_states,
                        &label_table,
                        source,
                        monitor_name_borrow,
                        handler_error_policy,
                        &health,
                    )
                {
                    packet_err = Some(e);
                }
                // Issue #24: NDP — walk the frame to ICMPv6 and drive the
                // detector, same in-borrow synchronous shape as ARP.
                #[cfg(feature = "ndp")]
                if let Some(watch) = ndp_watch.as_mut()
                    && packet_err.is_none()
                    && let Err(e) = dispatch_ndp(
                        watch,
                        view,
                        sink.as_mut(),
                        &mut state_map,
                        &mut counters,
                        &mut flow_states,
                        &label_table,
                        source,
                        monitor_name_borrow,
                        handler_error_policy,
                        &health,
                    )
                {
                    packet_err = Some(e);
                }
                // Issue #28: LLDP — L2 neighbor discovery, parsed per-frame
                // like ARP, same in-borrow synchronous shape.
                #[cfg(feature = "lldp")]
                if let Some(watch) = lldp_watch.as_mut()
                    && packet_err.is_none()
                    && let Err(e) = dispatch_lldp(
                        watch,
                        view,
                        sink.as_mut(),
                        &mut state_map,
                        &mut counters,
                        &mut flow_states,
                        &label_table,
                        source,
                        monitor_name_borrow,
                        handler_error_policy,
                        &health,
                    )
                {
                    packet_err = Some(e);
                }
                // Issue #28: CDP — Cisco L2 discovery (802.3 LLC/SNAP).
                #[cfg(feature = "cdp")]
                if let Some(watch) = cdp_watch.as_mut()
                    && packet_err.is_none()
                    && let Err(e) = dispatch_cdp(
                        watch,
                        view,
                        sink.as_mut(),
                        &mut state_map,
                        &mut counters,
                        &mut flow_states,
                        &label_table,
                        source,
                        monitor_name_borrow,
                        handler_error_policy,
                        &health,
                    )
                {
                    packet_err = Some(e);
                }
                // Issue #28: feed the asset inventory from this frame's L2/L3
                // discovery protocols (independent of the on_arp/on_ndp hooks).
                #[cfg(feature = "asset")]
                if let Some(aw) = asset_watch.as_mut()
                    && packet_err.is_none()
                    && let Err(e) = absorb_frame_assets(
                        aw,
                        view,
                        sink.as_mut(),
                        &mut state_map,
                        &mut counters,
                        &mut flow_states,
                        &label_table,
                        source,
                        monitor_name_borrow,
                        handler_error_policy,
                        &health,
                    )
                {
                    packet_err = Some(e);
                }
                driver.track_into(view, &mut events)
            })
            .await?;
        if let Some(e) = packet_err {
            return Err(e);
        }

        // A spurious wake (no retired block) leaves `last_ts == None`.
        let Some(ts) = last_ts else { continue };

        // Issue #23: borrow the learned ARP table (the drain's `&mut` borrow was
        // released above) so flow/session/lifecycle handlers can resolve IP→MAC
        // via `ctx.arp_table()`. Recomputed each iteration; dropped before the
        // next drain re-borrows `arp_watch` mutably.
        #[cfg(feature = "arp")]
        let arp_table_ref: ArpTableRef<'_> = arp_watch.as_ref().map(|w| &w.table);
        #[cfg(not(feature = "arp"))]
        let arp_table_ref: ArpTableRef<'_> = None;

        // AFTER BORROW: dispatch on owned data (sync + async, Send-safe).
        dispatch_tracked_events(
            &mut dispatcher,
            sink.as_mut(),
            &mut state_map,
            &mut counters,
            &mut events,
            source,
            monitor_name_borrow,
            &mut flow_states,
            &label_table,
            handler_error_policy,
            &mut flow_exporters,
            &health,
            arp_table_ref,
        )
        .await?;
        drain_protocol_slots(
            &mut dispatcher,
            &mut protocol_slots,
            &driver,
            sink.as_mut(),
            &mut state_map,
            &mut counters,
            &mut flow_states,
            ts,
            source,
            monitor_name_borrow,
            &label_table,
            handler_error_policy,
            &health,
            arp_table_ref,
        )?;

        // 0.24 Phase C4: record progress for the health handle — a packet
        // batch was processed; snapshot the tracker's active-flow count.
        health.record_event(driver.tracker().flow_count());
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
            &mut flow_states,
            &label_table,
            handler_error_policy,
            &mut flow_exporters,
            &health,
        )
        .await?;
    }

    // 0.24 Phase D: flush exporters (NDJSON/IPFIX writers may buffer).
    for exporter in flow_exporters.iter_mut() {
        let _ = exporter.flush();
    }

    Ok(())
}

/// 0.21 E.1: drive a monitor from an offline pcap file.
///
/// Single-source by design: pcap replay doesn't need
/// multi-interface fan-in or tick handlers (pcap timestamps
/// jitter relative to wall-clock; tick scheduling against them
/// is ambiguous). Runs to EOF, then calls the shared drain phase
/// so trailing flow ends + sink flushes still land.
///
/// On parse error from the pcap source, propagates the error
/// up — no partial-replay recovery.
#[cfg(all(feature = "pcap", feature = "tokio"))]
pub(crate) async fn replay_loop(
    monitor: Monitor,
    path: std::path::PathBuf,
    config: crate::pcap_source::AsyncPcapConfig,
) -> Result<()> {
    use std::pin::Pin;

    use futures_core::Stream;

    let Monitor {
        interfaces: _,
        #[cfg(feature = "af-xdp")]
            xdp_interfaces: _, // pcap replay has no live backend

        mut driver,
        mut dispatcher,
        mut protocol_slots,
        mut state_map,
        mut counters,
        mut sink,
        tick_handlers: _,
        detector_names: _,
        monitor_name,
        drain_timeout,
        broadcast_handles: _,
        pcap_source_path: _,
        pcap_speed_factor: _,
        mut flow_states,
        fanout: _,
        label_table,
        merge_rx: _, // replay is single-shard; no cross-shard merge
        handler_error_policy,
        backend_error_policy: _, // replay has no live capture backend
        capture_stats: _,        // pcap replay has no kernel ring to sample
        health,
        mut flow_exporters,
        flow_active_timeout: _, // active-timeout export is a live-loop concern
        packet_subs,
        // pcap replay has no kernel filter to set (the source isn't a socket).
        kernel_prefilter: _,
        promiscuous: _, // pcap replay has no live interface to set promiscuous
        #[cfg(feature = "af-xdp")]
            xdp_queues: _, // pcap replay has no live AF_XDP backend
        #[cfg(feature = "af-xdp")]
            injected_xdp: _, // pcap replay has no live AF_XDP backend
        #[cfg(feature = "arp")]
        mut arp_watch, // ARP detection works on offline replay too
        #[cfg(feature = "ndp")]
        mut ndp_watch,
        #[cfg(feature = "lldp")]
        mut lldp_watch,
        #[cfg(feature = "cdp")]
        mut cdp_watch,
        #[cfg(feature = "asset")]
        mut asset_watch,
    } = monitor;
    let monitor_name_borrow: Option<&str> = monitor_name.as_deref();

    let mut source = crate::pcap_source::AsyncPcapSource::open_with_config(&path, config).await?;
    let mut events: Vec<FsEvent<FlowKey>> = Vec::with_capacity(64);
    // 0.25 A1: packet-tier dispatch also runs on offline replay.
    let pkt_extractor = packet_field_extractor();

    // 0.24 Phase C4: the pcap source is open and replay is starting — the
    // same readiness/liveness handle works for offline replay.
    health.mark_started();
    health.mark_sockets_open();

    loop {
        // Pin the stream + poll the next packet. The source's
        // `Stream` impl drives the underlying spawn_blocking
        // reader task; `None` = EOF.
        let next = std::future::poll_fn(|cx| Pin::new(&mut source).poll_next(cx)).await;
        let pkt = match next {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Err(e),
            None => break,
        };

        let view = flowscope::PacketView::new(&pkt.data, pkt.timestamp);

        // 0.25 A1: packet-tier subs fire before tracking, as on the live path.
        if !packet_subs.is_empty() {
            dispatch_packet_subs(
                &packet_subs,
                view,
                &pkt_extractor,
                sink.as_mut(),
                &mut state_map,
                &mut counters,
                &mut flow_states,
                &label_table,
                SourceIdx(0),
                monitor_name_borrow,
                handler_error_policy,
                &health,
            )?;
        }

        // Issue #12: ARP detection on offline replay, mirroring the live path.
        #[cfg(feature = "arp")]
        if let Some(watch) = arp_watch.as_mut() {
            dispatch_arp(
                watch,
                view,
                sink.as_mut(),
                &mut state_map,
                &mut counters,
                &mut flow_states,
                &label_table,
                SourceIdx(0),
                monitor_name_borrow,
                handler_error_policy,
                &health,
            )?;
        }
        // Issue #24: NDP detection on offline replay.
        #[cfg(feature = "ndp")]
        if let Some(watch) = ndp_watch.as_mut() {
            dispatch_ndp(
                watch,
                view,
                sink.as_mut(),
                &mut state_map,
                &mut counters,
                &mut flow_states,
                &label_table,
                SourceIdx(0),
                monitor_name_borrow,
                handler_error_policy,
                &health,
            )?;
        }
        // Issue #28: LLDP/CDP L2 discovery on offline replay.
        #[cfg(feature = "lldp")]
        if let Some(watch) = lldp_watch.as_mut() {
            dispatch_lldp(
                watch,
                view,
                sink.as_mut(),
                &mut state_map,
                &mut counters,
                &mut flow_states,
                &label_table,
                SourceIdx(0),
                monitor_name_borrow,
                handler_error_policy,
                &health,
            )?;
        }
        #[cfg(feature = "cdp")]
        if let Some(watch) = cdp_watch.as_mut() {
            dispatch_cdp(
                watch,
                view,
                sink.as_mut(),
                &mut state_map,
                &mut counters,
                &mut flow_states,
                &label_table,
                SourceIdx(0),
                monitor_name_borrow,
                handler_error_policy,
                &health,
            )?;
        }
        // Issue #28: asset inventory on offline replay.
        #[cfg(feature = "asset")]
        if let Some(aw) = asset_watch.as_mut() {
            absorb_frame_assets(
                aw,
                view,
                sink.as_mut(),
                &mut state_map,
                &mut counters,
                &mut flow_states,
                &label_table,
                SourceIdx(0),
                monitor_name_borrow,
                handler_error_policy,
                &health,
            )?;
        }

        // Issue #23: expose the ARP table to flow/session/lifecycle handlers on
        // offline replay too (the ARP block's `&mut` borrow above is released).
        #[cfg(feature = "arp")]
        let arp_table_ref: ArpTableRef<'_> = arp_watch.as_ref().map(|w| &w.table);
        #[cfg(not(feature = "arp"))]
        let arp_table_ref: ArpTableRef<'_> = None;

        events.clear();
        driver.track_into(view, &mut events);
        dispatch_tracked_events(
            &mut dispatcher,
            sink.as_mut(),
            &mut state_map,
            &mut counters,
            &mut events,
            SourceIdx(0),
            monitor_name_borrow,
            &mut flow_states,
            &label_table,
            handler_error_policy,
            &mut flow_exporters,
            &health,
            arp_table_ref,
        )
        .await?;

        drain_protocol_slots(
            &mut dispatcher,
            &mut protocol_slots,
            &driver,
            sink.as_mut(),
            &mut state_map,
            &mut counters,
            &mut flow_states,
            pkt.timestamp,
            SourceIdx(0),
            monitor_name_borrow,
            &label_table,
            handler_error_policy,
            &health,
            arp_table_ref,
        )?;

        // 0.24 Phase C4: record replay progress for the health handle.
        health.record_event(driver.tracker().flow_count());
    }

    // EOF reached. Run the drain phase to land any trailing
    // events (flowscope's `finish()` synthesises FlowEnded
    // events for in-flight flows).
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
            &mut flow_states,
            &label_table,
            handler_error_policy,
            &mut flow_exporters,
            &health,
        )
        .await?;
    }

    // 0.24 Phase D: flush exporters after replay drain.
    for exporter in flow_exporters.iter_mut() {
        let _ = exporter.flush();
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
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    policy: HandlerErrorPolicy,
    flow_exporters: &mut [Box<dyn crate::export::FlowExporter>],
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    // Step 1: drain the central tracker.
    let mut leftover: Vec<FsEvent<FlowKey>> = Vec::new();
    driver.finish_into(&mut leftover);
    for evt in leftover.drain(..) {
        if Instant::now() >= deadline {
            return Ok(());
        }
        // 0.24 Phase D: export the flows finalized by `finish_into` (flows
        // still open at shutdown get a synthesized FlowEnded here).
        if !flow_exporters.is_empty()
            && let FsEvent::FlowEnded {
                key, stats, reason, ..
            } = &evt
        {
            let record = crate::export::FlowRecord::from_ended(key, stats, *reason);
            for exporter in flow_exporters.iter_mut() {
                exporter.export(&record);
            }
        }
        let res = match dispatch_lifecycle(
            dispatcher,
            sink,
            state_map,
            counters,
            evt.clone(),
            SourceIdx(0),
            monitor_name,
            flow_states,
            label_table,
            // Issue #23: the graceful-drain flush runs after the main loop; the
            // ARP table isn't threaded into shutdown (no IP→MAC lookups matter
            // while flushing trailing FlowEnded events).
            None,
        ) {
            Ok(()) => match dispatch_lifecycle_async(dispatcher, evt.clone()).await {
                // 0.25-B1: effect pass (drain) — same gating as the live path.
                Ok(()) if dispatcher.effect_handler_count() > 0 => {
                    dispatch_lifecycle_effects(
                        dispatcher,
                        sink,
                        state_map,
                        counters,
                        evt,
                        SourceIdx(0),
                        monitor_name,
                        flow_states,
                        label_table,
                    )
                    .await
                }
                other => other,
            },
            Err(e) => Err(e),
        };
        if let Err(e) = res {
            match policy {
                HandlerErrorPolicy::Propagate => return Err(e),
                HandlerErrorPolicy::Isolate => {
                    health.record_handler_error();
                    tracing::warn!(error = %e, "handler error isolated (drain)")
                }
            }
        }
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
        let mut ctx = Ctx::new(
            None,
            ts,
            SourceIdx(0),
            state_map,
            sink,
            counters,
            flow_states,
        );
        ctx.monitor_name = monitor_name;
        ctx.label_table = label_table;
        ctx.tracker = Some(driver.tracker());
        if let Err(e) = slot.drain_and_dispatch(dispatcher, &mut ctx) {
            match policy {
                HandlerErrorPolicy::Propagate => return Err(e),
                HandlerErrorPolicy::Isolate => {
                    health.record_handler_error();
                    tracing::warn!(error = %e, "handler error isolated (drain slot)")
                }
            }
        }
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

/// Round-robin readiness poll across the N captures. Returns
/// `Some(Ok(index))` for the next *readable* capture (the caller then drains
/// its borrowed batches in place), `Some(Err(_))` on a readiness error, or
/// `None` only when there are no captures.
///
/// Fair: `anchor` records the index just past the last serviced capture, so the
/// scan resumes there — a chatty interface can't starve the quiet ones. The
/// readiness guard from `poll_read_ready_mut` is dropped without clearing, so
/// the level-triggered fd stays ready and the caller's `readable()` resolves
/// immediately.
async fn ready_capture(caps: &mut [AnyBackend], anchor: &mut usize) -> Option<(usize, Result<()>)> {
    std::future::poll_fn(
        |cx: &mut Context<'_>| -> Poll<Option<(usize, Result<()>)>> {
            let n = caps.len();
            if n == 0 {
                return Poll::Ready(None);
            }
            let start = *anchor % n;
            for offset in 0..n {
                let i = (start + offset) % n;
                match caps[i].poll_read_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        *anchor = (i + 1) % n;
                        return Poll::Ready(Some((i, Ok(()))));
                    }
                    // 0.25 W1e: surface the failing index too, so a `Reopen` policy
                    // knows which backend to rebuild. Advance the anchor past it so a
                    // persistently-failing source doesn't monopolise the scan.
                    Poll::Ready(Err(e)) => {
                        *anchor = (i + 1) % n;
                        return Poll::Ready(Some((i, Err(e))));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
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

/// 0.22 §5.1: await the next cross-shard merge probe. When no merge
/// receiver is wired the future never resolves (the `select!` branch is
/// gated `if merge_rx.is_some()`, so this only runs in the `Some` case).
async fn recv_merge(
    rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<crate::monitor::merge::MergeRequest>>,
) -> Option<crate::monitor::merge::MergeRequest> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// 0.24 Phase C: await the next capture-telemetry sample tick. When no
/// `on_capture_stats` handler is registered the interval is `None` and the
/// future never resolves (the `select!` branch is gated `if
/// telemetry_interval.is_some()`, so this only runs in the `Some` case).
async fn next_telemetry_sample(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(int) => {
            int.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// 0.25 W1c: await the next active-timeout export tick. `None` → never fires
/// (gated off in the `select!`).
async fn next_active_export(slot: &mut Option<(tokio::time::Interval, Duration)>) {
    match slot {
        Some((int, _)) => {
            int.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// 0.25 W1c: emit an interim [`crate::export::FlowRecord`] for every live flow
/// that has been active for at least `period` since its last record, to each
/// registered exporter. Dedups per flow via `last_export` and prunes ended
/// flows from that map. Counters are cumulative-to-date (IPFIX active-timeout
/// semantics). Not on the per-packet hot path — runs once per `period`.
fn emit_active_flow_records(
    driver: &flowscope::driver::Driver<FiveTuple>,
    exporters: &mut [Box<dyn crate::export::FlowExporter>],
    last_export: &mut std::collections::HashMap<FlowKey, flowscope::Timestamp>,
    period: Duration,
) {
    use crate::export::FlowRecord;

    let now = flowscope::Timestamp::from_system_time(std::time::SystemTime::now());
    // Snapshot live flows first so the immutable tracker borrow is released
    // before we take `&mut exporters`. Cloning `FlowStats` per live flow once
    // per `period` is negligible (not the hot path).
    let snapshot: Vec<(FlowKey, flowscope::FlowStats)> = driver
        .tracker()
        .iter_active()
        .map(|af| (*af.key, af.stats.clone()))
        .collect();

    let mut live: std::collections::HashSet<FlowKey> =
        std::collections::HashSet::with_capacity(snapshot.len());
    for (key, stats) in &snapshot {
        live.insert(*key);
        let last = last_export.get(key).copied().unwrap_or(stats.started);
        if now.saturating_sub(last) >= period {
            let rec = FlowRecord::from_active(key, stats);
            for ex in exporters.iter_mut() {
                ex.export(&rec);
            }
            last_export.insert(*key, now);
        }
    }
    // Drop dedup entries for flows that have since ended.
    last_export.retain(|k, _| live.contains(k));
}

/// 0.24 Phase C: read each capture source's cumulative kernel counters,
/// fold them into a windowed [`CaptureTelemetry`], and fire the registered
/// `on_capture_stats` handler once per source.
///
/// Reads `cumulative_stats` (non-destructive at the API level — the inner
/// `Capture` accumulates the destructive `u32` kernel reads internally), so
/// it never disturbs the user-visible counters. A per-source stats read
/// that errors is logged and skipped rather than tearing down the monitor:
/// telemetry is best-effort observability.
#[allow(clippy::too_many_arguments)]
fn sample_and_fire_capture_stats(
    caps: &[AnyBackend],
    sampler: &mut crate::monitor::telemetry::TelemetrySampler,
    reg: &mut crate::monitor::telemetry::CaptureStatsRegistration,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    monitor_name: Option<&str>,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    let now = flowscope::Timestamp::from_system_time(SystemTime::now());
    // Accumulate the cumulative totals across sources for the health
    // handle (the per-source telemetry still goes to the user handler).
    let mut total_packets: u64 = 0;
    let mut total_drops: u64 = 0;
    for (i, cap) in caps.iter().enumerate() {
        let cum = match cap.cumulative_stats() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    source = i,
                    error = %e,
                    "capture stats read failed; skipping telemetry sample for this source"
                );
                continue;
            }
        };
        let telemetry = sampler.sample(i, cum);
        total_packets += telemetry.packets;
        total_drops += telemetry.drops;
        let mut ctx = Ctx::new(
            None,
            now,
            SourceIdx(i as u8),
            state_map,
            sink,
            counters,
            flow_states,
        );
        ctx.monitor_name = monitor_name;
        ctx.label_table = label_table;
        (reg.handler)(&telemetry, &mut ctx)?;
    }
    health.record_totals(total_packets, total_drops);
    Ok(())
}

/// Dispatch the lifecycle events drained from the central tracker — sync
/// handlers first, then async — and clear the buffer. The events are owned
/// (they don't borrow the capture ring), so this is safe to call **after** a
/// borrowed batch has been dropped, which is what keeps the borrowed run loop's
/// future `Send` (no `!Sync` ring borrow is held across the async `.await`).
///
/// Shared by the live run loop and the pcap replay loop so the dispatch
/// semantics stay identical (and are exercised by the cap-free
/// `monitor_replay` tests).
#[allow(clippy::too_many_arguments)]
async fn dispatch_tracked_events(
    dispatcher: &mut Dispatcher,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    events: &mut Vec<FsEvent<FlowKey>>,
    source: SourceIdx,
    monitor_name: Option<&str>,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    policy: HandlerErrorPolicy,
    flow_exporters: &mut [Box<dyn crate::export::FlowExporter>],
    health: &crate::monitor::health::HealthState,
    arp_table: ArpTableRef<'_>,
) -> Result<()> {
    for evt in events.drain(..) {
        // 0.24 Phase D: a flow just ended → build a FlowRecord and fan it
        // out to every registered exporter. Cheap no-op when none are
        // registered. Done before dispatch so exporters see the flow even
        // if a downstream handler errors under `Propagate`.
        if !flow_exporters.is_empty()
            && let FsEvent::FlowEnded {
                key, stats, reason, ..
            } = &evt
        {
            let record = crate::export::FlowRecord::from_ended(key, stats, *reason);
            for exporter in flow_exporters.iter_mut() {
                exporter.export(&record);
            }
        }
        // Sync handlers first, then async — but on the SAME event, so one error
        // is isolated per-event under `Isolate` (a malformed flow can't tear
        // down the pipeline).
        let res = match dispatch_lifecycle(
            dispatcher,
            sink,
            state_map,
            counters,
            evt.clone(),
            source,
            monitor_name,
            flow_states,
            label_table,
            arp_table,
        ) {
            Ok(()) => match dispatch_lifecycle_async(dispatcher, evt.clone()).await {
                // 0.25-B1: effect pass — gated so no-effect monitors skip
                // the whole `Ctx`-rebuilding translation (zero added cost).
                Ok(()) if dispatcher.effect_handler_count() > 0 => {
                    dispatch_lifecycle_effects(
                        dispatcher,
                        sink,
                        state_map,
                        counters,
                        evt,
                        source,
                        monitor_name,
                        flow_states,
                        label_table,
                    )
                    .await
                }
                other => other,
            },
            Err(e) => Err(e),
        };
        if let Err(e) = res {
            match policy {
                HandlerErrorPolicy::Propagate => return Err(e),
                HandlerErrorPolicy::Isolate => {
                    health.record_handler_error();
                    tracing::warn!(error = %e, "handler error isolated (per-event)")
                }
            }
        }
    }
    Ok(())
}

/// Drain each protocol slot's queued typed messages (e.g. parsed HTTP/DNS/TLS)
/// and dispatch them. The parsers were already fed by `driver.track_into`
/// (in-borrow); the messages they produced are owned, so this needs only a
/// shared `&driver` for the flow-tracker join — no capture-ring borrow.
#[allow(clippy::too_many_arguments)]
fn drain_protocol_slots(
    dispatcher: &mut Dispatcher,
    protocol_slots: &mut [Box<dyn crate::monitor::ProtocolSlot>],
    driver: &flowscope::driver::Driver<FiveTuple>,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    ts: flowscope::Timestamp,
    source: SourceIdx,
    monitor_name: Option<&str>,
    label_table: &flowscope::well_known::LabelTable,
    policy: HandlerErrorPolicy,
    health: &crate::monitor::health::HealthState,
    arp_table: ArpTableRef<'_>,
) -> Result<()> {
    for slot in protocol_slots.iter_mut() {
        let mut ctx = Ctx::new(None, ts, source, state_map, sink, counters, flow_states);
        ctx.monitor_name = monitor_name;
        ctx.label_table = label_table;
        ctx.tracker = Some(driver.tracker());
        // Issue #23: cross-protocol IP→MAC lookup for L7 (TLS/HTTP/DNS) handlers.
        ctx.arp_table = arp_table;
        if let Err(e) = slot.drain_and_dispatch(dispatcher, &mut ctx) {
            match policy {
                HandlerErrorPolicy::Propagate => return Err(e),
                HandlerErrorPolicy::Isolate => {
                    health.record_handler_error();
                    tracing::warn!(error = %e, "handler error isolated (per-slot)")
                }
            }
        }
    }
    Ok(())
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
#[allow(clippy::too_many_arguments)]
async fn fire_tick(
    tick_idx: usize,
    tick_handlers: &mut [crate::monitor::tick::TickRegistration],
    dispatcher: &mut Dispatcher,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    monitor_name: Option<&str>,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
) -> Result<()> {
    let reg = &mut tick_handlers[tick_idx];
    let tick = Tick {
        now: flowscope::Timestamp::from_system_time(SystemTime::now()),
        period: reg.period,
    };
    {
        let mut ctx = Ctx::new(
            None,
            tick.now,
            SourceIdx(0),
            state_map,
            sink,
            counters,
            flow_states,
        );
        ctx.monitor_name = monitor_name;
        ctx.label_table = label_table;
        (reg.handler)(&tick, &mut ctx)?;
    }
    {
        let mut ctx = Ctx::new(
            None,
            tick.now,
            SourceIdx(0),
            state_map,
            sink,
            counters,
            flow_states,
        );
        ctx.monitor_name = monitor_name;
        ctx.label_table = label_table;
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
                // 0.22 §2.6: async TcpRst synthesis mirrors the sync arm.
                let is_rst = reason == flowscope::EndReason::Rst;
                dispatcher
                    .dispatch_async(&FlowEnded::<Tcp>::new(key, reason, stats.clone(), l4, ts))
                    .await?;
                if is_rst {
                    dispatcher
                        .dispatch_async(&TcpRst::new(key, stats, ts))
                        .await?;
                }
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
        // 0.22 R2: one flat FlowPacket carrying `proto`; no per-L4
        // dispatch fan-out.
        FsEvent::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
        } => {
            dispatcher
                .dispatch_async(&FlowPacket::new(key.proto, key, side, len, tcp, ts))
                .await?;
        }
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

/// 0.25 A1: dispatch the packet-tier subscriptions for one frame.
///
/// Extracts the 5-tuple once (directional — `a`=src, `b`=dst), builds one
/// `Ctx`, and invokes every sub whose [`Predicate`](crate::monitor::subscription::Predicate)
/// matches the frame's fields. Synchronous — called from inside the zero-copy
/// drain (or the replay packet loop) before flow tracking, so the borrowed
/// `PacketView` reaches the handler with no copy. Returns `Err` only under
/// [`HandlerErrorPolicy::Propagate`]; `Isolate` records the error on the
/// health handle and continues.
///
/// Frames the extractor skips (ARP / non-IP / malformed) match no sub and
/// return `Ok(())` immediately.
#[allow(clippy::too_many_arguments)]
fn dispatch_packet_subs(
    subs: &[PacketSubscription],
    view: PacketView<'_>,
    extractor: &FiveTuple,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    source: SourceIdx,
    monitor_name: Option<&str>,
    policy: HandlerErrorPolicy,
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    let Some((key, fields)) = PacketFields::extract(view, extractor) else {
        return Ok(());
    };
    // Build the Ctx once and reuse it across subs (sequential dispatch). The
    // packet tier is pre-flow, so `tracker` is `None` (no flow correlation
    // before this frame is tracked).
    let mut ctx = Ctx {
        flow: Some(key),
        ts: view.timestamp,
        source,
        monitor_name,
        state_map,
        sink,
        counters,
        flow_states,
        label_table,
        tracker: None,
        arp_table: None,
    };
    for sub in subs {
        if sub.predicate.eval(&fields)
            && let Err(e) = (sub.handler)(&view, &mut ctx)
        {
            match policy {
                HandlerErrorPolicy::Propagate => return Err(e),
                HandlerErrorPolicy::Isolate => {
                    health.record_handler_error();
                    tracing::warn!(error = %e, "packet-sub handler error isolated");
                }
            }
        }
    }
    Ok(())
}

/// Issue #12: parse one L2 frame for ARP and drive the detector. Called in
/// the zero-copy drain (and the replay loop) for every captured frame when
/// an ARP hook is armed. Synchronous — its borrows drop before any `.await`,
/// keeping the run-loop future `Send`. Non-ARP frames (the overwhelming
/// majority) cost one `parse_frame` early-return and nothing else.
///
/// Order: learn the binding (`observe`) first so the anomaly is derived
/// against the *prior* table state, then dispatch the raw-message handlers
/// and finally the anomaly handlers — all over one shared `Ctx`.
#[cfg(feature = "arp")]
#[allow(clippy::too_many_arguments)]
fn dispatch_arp(
    watch: &mut crate::monitor::arp::ArpWatch,
    view: PacketView<'_>,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    source: SourceIdx,
    monitor_name: Option<&str>,
    policy: HandlerErrorPolicy,
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    let Some(msg) = flowscope::arp::parse_frame(view.frame) else {
        return Ok(());
    };
    // Learn the binding and derive an anomaly against the prior table state.
    // `ArpAnomaly` is `Copy` and doesn't borrow `watch`, so the handler loops
    // below can re-borrow `watch.{msg,anomaly}_handlers` immutably.
    let anomaly = watch.observe(&msg, view.timestamp);

    let mut ctx = Ctx {
        flow: None, // ARP is L2 — no 5-tuple flow key.
        ts: view.timestamp,
        source,
        monitor_name,
        state_map,
        sink,
        counters,
        flow_states,
        label_table,
        tracker: None,
        // Issue #19: the binding was already learned by `observe` above, so
        // this shared borrow exposes the table *including* the current frame
        // to `Ctx::arp_table()` in the handlers below.
        arp_table: Some(&watch.table),
    };

    // Helper: apply the error policy uniformly to one handler result.
    macro_rules! guard {
        ($res:expr, $what:literal) => {
            if let Err(e) = $res {
                match policy {
                    HandlerErrorPolicy::Propagate => return Err(e),
                    HandlerErrorPolicy::Isolate => {
                        health.record_handler_error();
                        tracing::warn!(error = %e, concat!($what, " handler error isolated"));
                    }
                }
            }
        };
    }

    for handler in &watch.msg_handlers {
        guard!(handler(&msg, &mut ctx), "arp");
    }
    if let Some(anomaly) = anomaly {
        for handler in &watch.anomaly_handlers {
            guard!(handler(&anomaly, &mut ctx), "arp-anomaly");
        }
    }
    Ok(())
}

/// Issue #24: walk one frame to its ICMPv6 message and drive the NDP detector
/// — the IPv6 sibling of [`dispatch_arp`]. NDP rides ICMPv6, so unlike ARP's
/// free L2 `parse_frame` this parses the layer stack (`view.layers()`) to reach
/// the ICMPv6 slice. Non-ICMPv6 frames cost the layers parse + an early return.
/// Synchronous — borrows drop before any `.await` (preserves `Send`).
#[cfg(feature = "ndp")]
#[allow(clippy::too_many_arguments)]
fn dispatch_ndp(
    watch: &mut crate::monitor::ndp::NdpWatch,
    view: PacketView<'_>,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    source: SourceIdx,
    monitor_name: Option<&str>,
    policy: HandlerErrorPolicy,
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    // Walk to ICMPv6; only NS/NA (types 135/136) parse into an NdpMessage.
    let Ok(layers) = view.layers() else {
        return Ok(());
    };
    let Some(icmp) = layers.icmpv6() else {
        return Ok(());
    };
    let Some(msg) = flowscope::ndp::parse_icmpv6(icmp.bytes()) else {
        return Ok(());
    };
    let anomaly = watch.observe(&msg, view.timestamp);

    let mut ctx = Ctx {
        flow: None, // NDP is L3 control plane — no 5-tuple flow key.
        ts: view.timestamp,
        source,
        monitor_name,
        state_map,
        sink,
        counters,
        flow_states,
        label_table,
        tracker: None,
        arp_table: None, // the ARP (IPv4) table; NDP's IPv6 table isn't exposed on Ctx.
    };

    macro_rules! guard {
        ($res:expr, $what:literal) => {
            if let Err(e) = $res {
                match policy {
                    HandlerErrorPolicy::Propagate => return Err(e),
                    HandlerErrorPolicy::Isolate => {
                        health.record_handler_error();
                        tracing::warn!(error = %e, concat!($what, " handler error isolated"));
                    }
                }
            }
        };
    }

    for handler in &watch.msg_handlers {
        guard!(handler(&msg, &mut ctx), "ndp");
    }
    if let Some(anomaly) = anomaly {
        for handler in &watch.anomaly_handlers {
            guard!(handler(&anomaly, &mut ctx), "ndp-anomaly");
        }
    }
    Ok(())
}

/// Issue #28: parse one L2 frame as LLDP and feed `on_lldp` — the IEEE
/// 802.1AB sibling of [`dispatch_arp`]. `flowscope::lldp::parse_frame` takes
/// the FULL Ethernet frame (it validates the LLDP multicast dst MAC +
/// EtherType `0x88cc`), so non-LLDP frames cost one cheap header check + an
/// early return. Synchronous — borrows drop before any `.await` (preserves
/// `Send`). No anomaly pipeline in v1.
#[cfg(feature = "lldp")]
#[allow(clippy::too_many_arguments)]
fn dispatch_lldp(
    watch: &mut crate::monitor::lldp::LldpWatch,
    view: PacketView<'_>,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    source: SourceIdx,
    monitor_name: Option<&str>,
    policy: HandlerErrorPolicy,
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    let Some(msg) = flowscope::lldp::parse_frame(view.frame) else {
        return Ok(());
    };

    let mut ctx = Ctx {
        flow: None, // LLDP is L2 — no 5-tuple flow key.
        ts: view.timestamp,
        source,
        monitor_name,
        state_map,
        sink,
        counters,
        flow_states,
        label_table,
        tracker: None,
        arp_table: None,
    };

    macro_rules! guard {
        ($res:expr, $what:literal) => {
            if let Err(e) = $res {
                match policy {
                    HandlerErrorPolicy::Propagate => return Err(e),
                    HandlerErrorPolicy::Isolate => {
                        health.record_handler_error();
                        tracing::warn!(error = %e, concat!($what, " handler error isolated"));
                    }
                }
            }
        };
    }

    for handler in &watch.msg_handlers {
        guard!(handler(&msg, &mut ctx), "lldp");
    }
    Ok(())
}

/// Issue #28: parse one L2 frame as CDP and feed `on_cdp`. Like LLDP,
/// `flowscope::cdp::parse_frame` validates the full Ethernet + LLC/SNAP header
/// (dst MAC `01:00:0c:cc:cc:cc`, OUI `00:00:0c`, PID `0x2000`), so non-CDP
/// frames return early. No anomaly pipeline in v1.
#[cfg(feature = "cdp")]
#[allow(clippy::too_many_arguments)]
fn dispatch_cdp(
    watch: &mut crate::monitor::cdp::CdpWatch,
    view: PacketView<'_>,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    source: SourceIdx,
    monitor_name: Option<&str>,
    policy: HandlerErrorPolicy,
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    let Some(msg) = flowscope::cdp::parse_frame(view.frame) else {
        return Ok(());
    };

    let mut ctx = Ctx {
        flow: None, // CDP is L2 — no 5-tuple flow key.
        ts: view.timestamp,
        source,
        monitor_name,
        state_map,
        sink,
        counters,
        flow_states,
        label_table,
        tracker: None,
        arp_table: None,
    };

    macro_rules! guard {
        ($res:expr, $what:literal) => {
            if let Err(e) = $res {
                match policy {
                    HandlerErrorPolicy::Propagate => return Err(e),
                    HandlerErrorPolicy::Isolate => {
                        health.record_handler_error();
                        tracing::warn!(error = %e, concat!($what, " handler error isolated"));
                    }
                }
            }
        };
    }

    for handler in &watch.msg_handlers {
        guard!(handler(&msg, &mut ctx), "cdp");
    }
    Ok(())
}

/// Issue #28: feed the passive asset [`Inventory`](flowscope::Inventory) from
/// one frame's L2/L3 discovery protocols. Independent of the `on_arp`/`on_ndp`
/// hooks — it re-parses the frame for whichever source features are compiled in
/// (ARP / NDP / LLDP / CDP), folds each into an `Asset` keyed by MAC, and fires
/// `on_asset` only when the merged record is new or changed. The re-parse is a
/// cheap header check that early-returns on non-discovery frames.
#[cfg(feature = "asset")]
#[allow(clippy::too_many_arguments)]
fn absorb_frame_assets(
    aw: &mut crate::monitor::asset::AssetWatch,
    view: PacketView<'_>,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    source: SourceIdx,
    monitor_name: Option<&str>,
    policy: HandlerErrorPolicy,
    health: &crate::monitor::health::HealthState,
) -> Result<()> {
    let mut ctx = Ctx {
        flow: None, // asset records are L2-keyed — no 5-tuple flow key.
        ts: view.timestamp,
        source,
        monitor_name,
        state_map,
        sink,
        counters,
        flow_states,
        label_table,
        tracker: None,
        arp_table: None,
    };

    macro_rules! guard {
        ($res:expr) => {
            if let Err(e) = $res {
                match policy {
                    HandlerErrorPolicy::Propagate => return Err(e),
                    HandlerErrorPolicy::Isolate => {
                        health.record_handler_error();
                        tracing::warn!(error = %e, "asset handler error isolated");
                    }
                }
            }
        };
    }
    // Absorb one update; fire `on_asset` only if the inventory record changed.
    macro_rules! feed {
        ($update:expr) => {
            if let Some(merged) = aw.absorb($update, view.timestamp) {
                for handler in &aw.handlers {
                    guard!(handler(&merged, &mut ctx));
                }
            }
        };
    }

    #[cfg(feature = "arp")]
    if let Some(m) = flowscope::arp::parse_frame(view.frame) {
        feed!(flowscope::Asset::from_arp(&m));
    }
    #[cfg(feature = "ndp")]
    if let Ok(layers) = view.layers()
        && let Some(icmp) = layers.icmpv6()
        && let Some(m) = flowscope::ndp::parse_icmpv6(icmp.bytes())
        && let Some(a) = flowscope::Asset::from_ndp(&m)
    {
        feed!(a);
    }
    #[cfg(feature = "lldp")]
    if let Some(m) = flowscope::lldp::parse_frame(view.frame)
        && let Some(a) = flowscope::Asset::from_lldp(&m)
    {
        feed!(a);
    }
    #[cfg(feature = "cdp")]
    if let Some(m) = flowscope::cdp::parse_frame(view.frame) {
        // `parse_frame` validated frame.len() >= 22, so the src MAC is present.
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&view.frame[6..12]);
        feed!(flowscope::Asset::from_cdp(&m, flowscope::MacAddr(mac)));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn dispatch_lifecycle(
    dispatcher: &mut Dispatcher,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    evt: FsEvent<FlowKey>,
    source: SourceIdx,
    monitor_name: Option<&str>,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
    arp_table: ArpTableRef<'_>,
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
                flow_states: &mut *flow_states,
                label_table,
                tracker: None,
                // Issue #23: cross-protocol IP→MAC lookup for lifecycle handlers.
                arp_table,
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
                // 0.22 §2.6: synthesise a TcpRst alongside FlowEnded<Tcp>
                // when the close reason is RST. Cheap — the struct is
                // built only on real RSTs; dispatch is a no-op when no
                // TcpRst handler is registered.
                let is_rst = reason == flowscope::EndReason::Rst;
                dispatch_one!(
                    FlowEnded<Tcp>,
                    FlowEnded::<Tcp>::new(key, reason, stats.clone(), l4, ts),
                    Some(key),
                    ts
                );
                if is_rst {
                    dispatch_one!(TcpRst, TcpRst::new(key, stats, ts), Some(key), ts);
                }
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
        // 0.22 R2: one flat FlowPacket carrying `proto`.
        FsEvent::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
        } => {
            dispatch_one!(
                FlowPacket,
                FlowPacket::new(key.proto, key, side, len, tcp, ts),
                Some(key),
                ts
            );
        }
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

/// 0.25-B1: effect sibling of [`dispatch_lifecycle`]. Translates each
/// `FsEvent` into the same typed payload, builds a `Ctx` per arm
/// (mirroring the sync pass so handlers read the same state), and runs
/// [`Dispatcher::dispatch_effects`] — the async read-`&Ctx` /
/// write-`Effects` pass.
///
/// Fires **after** the sync ([`dispatch_lifecycle`]) and async
/// ([`dispatch_lifecycle_async`]) passes for the same event. The caller
/// gates this on `dispatcher.effect_handler_count() > 0` so monitors with
/// no effect handlers pay nothing (not even this function call). Holds
/// `&mut Ctx` across `.await`, which is `Send`-safe because every `Ctx`
/// field is `Send` (notably `AnomalySink: Send`) — see
/// `tests/monitor_send.rs`.
#[allow(clippy::too_many_arguments)]
async fn dispatch_lifecycle_effects(
    dispatcher: &mut Dispatcher,
    sink: &mut dyn AnomalySink,
    state_map: &mut StateMap,
    counters: &mut CounterRegistry,
    evt: FsEvent<FlowKey>,
    source: SourceIdx,
    monitor_name: Option<&str>,
    flow_states: &mut crate::ctx::FlowStateRegistry,
    label_table: &flowscope::well_known::LabelTable,
) -> Result<()> {
    // Same per-arm `Ctx` construction as `dispatch_lifecycle`; the
    // dispatch call is the async `dispatch_effects` instead of the sync
    // `dispatch`. Macro inlines the borrow so each `&mut` is scoped to a
    // single dispatch (hoisting into a closure trips HRTB inference).
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
                flow_states: &mut *flow_states,
                label_table,
                tracker: None,
                arp_table: None,
            };
            dispatcher
                .dispatch_effects::<$ty>(&$payload, &mut ctx)
                .await?;
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
                let is_rst = reason == flowscope::EndReason::Rst;
                dispatch_one!(
                    FlowEnded<Tcp>,
                    FlowEnded::<Tcp>::new(key, reason, stats.clone(), l4, ts),
                    Some(key),
                    ts
                );
                if is_rst {
                    dispatch_one!(TcpRst, TcpRst::new(key, stats, ts), Some(key), ts);
                }
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
        } => {
            dispatch_one!(
                FlowPacket,
                FlowPacket::new(key.proto, key, side, len, tcp, ts),
                Some(key),
                ts
            );
        }
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

#[cfg(test)]
mod active_export_tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use flowscope::driver::Driver;
    use flowscope::extract::FiveTuple;

    use super::*;
    use crate::export::{FlowExporter, FlowRecord};

    /// Collects every exported record (`FlowRecord` is `Copy`).
    struct Collect(Arc<Mutex<Vec<FlowRecord>>>);
    impl FlowExporter for Collect {
        fn export(&mut self, r: &FlowRecord) {
            self.0.lock().unwrap().push(*r);
        }
    }

    fn tcp_frame() -> Vec<u8> {
        use etherparse::PacketBuilder;
        let b = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(1234, 80, 0, 1024);
        let mut frame = Vec::new();
        b.write(&mut frame, &[]).unwrap();
        frame
    }

    #[test]
    fn emit_active_records_one_per_window_with_dedup() {
        // A live flow whose `started` is far in the past (1970+1000s) so the
        // active window has trivially elapsed against the wall clock.
        let mut driver = Driver::builder(FiveTuple::bidirectional()).build();
        let frame = tcp_frame();
        let ts = flowscope::Timestamp::from_unix_f64(1000.0);
        let mut events = Vec::new();
        driver.track_into(flowscope::PacketView::new(&frame, ts), &mut events);
        assert!(driver.tracker().flow_count() >= 1, "flow should be tracked");

        let sink = Arc::new(Mutex::new(Vec::new()));
        let mut exporters: Vec<Box<dyn FlowExporter>> = vec![Box::new(Collect(sink.clone()))];
        let mut last_export = std::collections::HashMap::new();

        // First sweep: the flow is older than the 1s window -> one ongoing record.
        emit_active_flow_records(
            &driver,
            &mut exporters,
            &mut last_export,
            Duration::from_secs(1),
        );
        {
            let recs = sink.lock().unwrap();
            assert_eq!(recs.len(), 1, "one interim record for the live flow");
            assert!(recs[0].is_ongoing(), "interim record has reason == None");
        }

        // Second sweep right after: dedup -- `last_export` was just stamped, so
        // less than the 1s window has elapsed -> no new record.
        emit_active_flow_records(
            &driver,
            &mut exporters,
            &mut last_export,
            Duration::from_secs(1),
        );
        assert_eq!(
            sink.lock().unwrap().len(),
            1,
            "dedup: no second record within the active window"
        );
    }
}
