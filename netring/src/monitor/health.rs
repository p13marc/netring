//! Monitor health handle (0.24 Phase C4).
//!
//! A [`MonitorHealth`] is a cheap, cloneable, `Arc`-backed view of a
//! running monitor's liveness and readiness — the thing a `/healthz` /
//! `/readyz` endpoint reads. Obtain one from
//! [`Monitor::health`](crate::monitor::Monitor::health) *before* you
//! spawn the run loop, clone it into your HTTP handler, and poll it; the
//! run loop updates the shared state as it goes.
//!
//! The split mirrors Kubernetes probe semantics:
//!
//! - **Readiness** ([`is_ready`](MonitorHealth::is_ready)) — the capture
//!   sockets are open and the run loop is servicing them. Flip this into
//!   a `/readyz` probe so traffic / dependents only start once the
//!   monitor is actually listening.
//! - **Liveness** ([`is_live`](MonitorHealth::is_live)) — the loop is
//!   making progress: an event arrived within the liveness window, or
//!   we're still inside the startup grace. A passive capture on a quiet
//!   link stays live (uptime grace) without faking traffic.
//!
//! Everything is lock-free (atomics); reading from a hot HTTP path costs
//! a handful of relaxed loads.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Shared health state. The run loop owns the writer side (via the
/// `record_*` / `mark_*` methods); [`MonitorHealth`] clones expose the
/// reader side. One per monitor.
pub(crate) struct HealthState {
    /// Set once, when the run loop enters. `None` until then, so
    /// `uptime()` reads 0 for a built-but-not-yet-run monitor.
    started: OnceLock<Instant>,
    /// Flipped true once all capture sockets are open and the loop is
    /// about to start servicing them.
    sockets_open: AtomicBool,
    /// Flipped true on the first packet/tick event.
    first_event: AtomicBool,
    /// Millis since `started` of the most recent event. Meaningless
    /// until `first_event` is set.
    last_event_ms: AtomicU64,
    /// Active flows in the central tracker as of the last event.
    active_flows: AtomicUsize,
    /// Cumulative packets / drops across all sources as of the last
    /// telemetry sample (0 until the first `on_capture_stats`-style
    /// sample, which is independent of `record_event`).
    packets: AtomicU64,
    drops: AtomicU64,
}

impl HealthState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            started: OnceLock::new(),
            sockets_open: AtomicBool::new(false),
            first_event: AtomicBool::new(false),
            last_event_ms: AtomicU64::new(0),
            active_flows: AtomicUsize::new(0),
            packets: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        })
    }

    /// Stamp the run-loop start instant (idempotent — the first call
    /// wins). Called once as the loop is entered.
    pub(crate) fn mark_started(&self) {
        let _ = self.started.set(Instant::now());
    }

    /// Mark the capture sockets open + loop servicing (readiness true).
    pub(crate) fn mark_sockets_open(&self) {
        self.sockets_open.store(true, Ordering::Relaxed);
    }

    /// Record that an event (packet batch or tick) was just processed,
    /// with the tracker's current active-flow count.
    pub(crate) fn record_event(&self, active_flows: usize) {
        let elapsed = self
            .started
            .get()
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        self.last_event_ms.store(elapsed, Ordering::Relaxed);
        self.active_flows.store(active_flows, Ordering::Relaxed);
        self.first_event.store(true, Ordering::Relaxed);
    }

    /// Record the latest cumulative packet/drop totals (from a telemetry
    /// sample). Independent of `record_event` so it works even when the
    /// only configured signal is `on_capture_stats`.
    pub(crate) fn record_totals(&self, packets: u64, drops: u64) {
        self.packets.store(packets, Ordering::Relaxed);
        self.drops.store(drops, Ordering::Relaxed);
    }

    fn uptime(&self) -> Duration {
        self.started
            .get()
            .map(Instant::elapsed)
            .unwrap_or(Duration::ZERO)
    }

    fn last_event_age(&self) -> Option<Duration> {
        if !self.first_event.load(Ordering::Relaxed) {
            return None;
        }
        let last = Duration::from_millis(self.last_event_ms.load(Ordering::Relaxed));
        // `uptime - last_event_elapsed`, floored at zero (the two reads
        // race, so uptime can momentarily read smaller than `last`).
        Some(self.uptime().saturating_sub(last))
    }
}

/// A cheap, cloneable view of a running monitor's health. See the
/// [module docs](self) for the readiness vs liveness split.
///
/// Obtain via [`Monitor::health`](crate::monitor::Monitor::health). Clone
/// it freely — every clone shares the same atomics.
#[derive(Clone)]
pub struct MonitorHealth {
    inner: Arc<HealthState>,
}

impl MonitorHealth {
    pub(crate) fn new(inner: Arc<HealthState>) -> Self {
        Self { inner }
    }

    /// Wall-clock time since the run loop started. `Duration::ZERO`
    /// before the monitor is run.
    pub fn uptime(&self) -> Duration {
        self.inner.uptime()
    }

    /// Time since the last processed event (packet batch or tick).
    /// `None` if no event has been seen yet.
    pub fn last_event_age(&self) -> Option<Duration> {
        self.inner.last_event_age()
    }

    /// Active flows in the central tracker as of the last event.
    pub fn active_flows(&self) -> usize {
        self.inner.active_flows.load(Ordering::Relaxed)
    }

    /// Cumulative packets across all sources as of the last telemetry
    /// sample (requires an `on_capture_stats` / `capture_*` registration;
    /// otherwise stays 0).
    pub fn packets(&self) -> u64 {
        self.inner.packets.load(Ordering::Relaxed)
    }

    /// Cumulative kernel drops across all sources as of the last
    /// telemetry sample.
    pub fn drops(&self) -> u64 {
        self.inner.drops.load(Ordering::Relaxed)
    }

    /// `true` once at least one event (packet or tick) has been
    /// processed. A weaker signal than [`is_ready`](Self::is_ready) — a
    /// quiet link can be ready without having seen traffic.
    pub fn has_seen_traffic(&self) -> bool {
        self.inner.first_event.load(Ordering::Relaxed)
    }

    /// **Readiness**: the capture sockets are open and the run loop is
    /// servicing them. The `/readyz` signal — `false` before the loop
    /// has opened its sockets, `true` for the rest of the run.
    pub fn is_ready(&self) -> bool {
        self.inner.sockets_open.load(Ordering::Relaxed)
    }

    /// **Liveness**: the loop is making progress. `true` when an event
    /// arrived within `window`, *or* the monitor has been up for less
    /// than `window` (startup grace, so a slow first packet doesn't read
    /// as dead). `false` only once `window` has elapsed both since start
    /// and since the last event — i.e. a genuine stall.
    ///
    /// Pick `window` as a few times your slowest expected inter-event
    /// gap (for a passive capture, a few times the quietest tick period).
    pub fn is_live(&self, window: Duration) -> bool {
        match self.last_event_age() {
            Some(age) => age < window,
            // No event yet: live as long as we're still in startup grace.
            None => self.uptime() < window,
        }
    }

    /// A consistent point-in-time snapshot of the readable fields —
    /// handy for serializing one health record without N racy loads.
    pub fn snapshot(&self) -> MonitorHealthSnapshot {
        MonitorHealthSnapshot {
            uptime: self.uptime(),
            last_event_age: self.last_event_age(),
            active_flows: self.active_flows(),
            packets: self.packets(),
            drops: self.drops(),
            ready: self.is_ready(),
            seen_traffic: self.has_seen_traffic(),
        }
    }
}

impl std::fmt::Debug for MonitorHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorHealth")
            .field("uptime", &self.uptime())
            .field("ready", &self.is_ready())
            .field("active_flows", &self.active_flows())
            .finish_non_exhaustive()
    }
}

/// A consistent snapshot of [`MonitorHealth`] fields. `is_live` isn't
/// included — it's a function of `last_event_age` + `uptime` against a
/// caller-chosen window, both present here.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MonitorHealthSnapshot {
    /// Time since the run loop started.
    pub uptime: Duration,
    /// Time since the last event, or `None` if none yet.
    pub last_event_age: Option<Duration>,
    /// Active flows as of the last event.
    pub active_flows: usize,
    /// Cumulative packets as of the last telemetry sample.
    pub packets: u64,
    /// Cumulative drops as of the last telemetry sample.
    pub drops: u64,
    /// Readiness (sockets open + loop servicing).
    pub ready: bool,
    /// Whether any traffic has been seen.
    pub seen_traffic: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unstarted_monitor_reads_zero_uptime_and_no_event() {
        let h = MonitorHealth::new(HealthState::new());
        assert_eq!(h.uptime(), Duration::ZERO);
        assert_eq!(h.last_event_age(), None);
        assert!(!h.is_ready());
        assert!(!h.has_seen_traffic());
    }

    #[test]
    fn readiness_flips_on_sockets_open_not_on_traffic() {
        let state = HealthState::new();
        let h = MonitorHealth::new(state.clone());
        state.mark_started();
        assert!(!h.is_ready(), "not ready before sockets open");
        state.mark_sockets_open();
        assert!(
            h.is_ready(),
            "ready once sockets open, even with no traffic"
        );
        assert!(!h.has_seen_traffic());
    }

    #[test]
    fn liveness_uses_startup_grace_then_last_event_age() {
        let state = HealthState::new();
        let h = MonitorHealth::new(state.clone());
        state.mark_started();
        // No event yet, but just started → live within a generous window.
        assert!(h.is_live(Duration::from_secs(60)));
        // ...and dead against a zero window (uptime is already > 0).
        assert!(!h.is_live(Duration::ZERO));

        // After an event, liveness tracks last_event_age. The event was
        // ~now, so a generous window is live; a zero window is not.
        state.record_event(3);
        assert!(h.has_seen_traffic());
        assert_eq!(h.active_flows(), 3);
        assert!(h.is_live(Duration::from_secs(60)));
        assert!(!h.is_live(Duration::ZERO));
    }

    #[test]
    fn totals_track_latest_telemetry_sample() {
        let state = HealthState::new();
        let h = MonitorHealth::new(state.clone());
        assert_eq!(h.packets(), 0);
        state.record_totals(1000, 5);
        assert_eq!(h.packets(), 1000);
        assert_eq!(h.drops(), 5);
        // A later, larger sample overwrites (absolute, not additive).
        state.record_totals(2500, 12);
        assert_eq!(h.packets(), 2500);
        assert_eq!(h.drops(), 12);
    }

    #[test]
    fn snapshot_is_internally_consistent() {
        let state = HealthState::new();
        let h = MonitorHealth::new(state.clone());
        state.mark_started();
        state.mark_sockets_open();
        state.record_event(7);
        state.record_totals(42, 1);
        let snap = h.snapshot();
        assert!(snap.ready);
        assert!(snap.seen_traffic);
        assert_eq!(snap.active_flows, 7);
        assert_eq!(snap.packets, 42);
        assert_eq!(snap.drops, 1);
        assert!(snap.last_event_age.is_some());
    }
}
