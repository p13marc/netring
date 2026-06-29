//! Overload detection with hysteresis (issue #54, detection half).
//!
//! Drives an [`OverloadState`] off the windowed
//! [`CaptureTelemetry::drop_rate`](crate::monitor::CaptureTelemetry::drop_rate),
//! the same "consumer can't keep up" signal the run loop already samples. The
//! capture pipeline has no upstream backpressure — the NIC keeps sending — so
//! the useful lever is to *know* when you're shedding and react (alert,
//! autoscale, shed at your own sink, or bypass elephant flows). This module is
//! the debounced **signal**; the shedding *action* is the caller's policy.
//!
//! Hysteresis (Suricata's emergency-mode model) avoids flapping: enter
//! `Emergency` the moment the drop rate crosses `enter_drop_rate`, but only
//! return to `Normal` after the rate has stayed below `recover_drop_rate` for
//! `recover_windows` consecutive samples.
//!
//! Wire it off [`on_capture_stats`](crate::monitor::MonitorBuilder::on_capture_stats):
//!
//! ```no_run
//! # #[cfg(all(feature = "flow", feature = "tokio"))] fn demo() {
//! use std::time::Duration;
//! use netring::monitor::Monitor;
//! use netring::monitor::overload::{OverloadConfig, OverloadDetector, OverloadState};
//!
//! let mut overload = OverloadDetector::new(OverloadConfig::default());
//! Monitor::builder()
//!     .interface("eth0")
//!     .on_capture_stats(Duration::from_secs(1), move |t, _ctx| {
//!         if let Some(state) = overload.observe(t.drop_rate) {
//!             match state {
//!                 OverloadState::Emergency => eprintln!("OVERLOAD — shedding {:.1}%", t.drop_rate * 100.0),
//!                 OverloadState::Normal => eprintln!("recovered"),
//!                 _ => {} // OverloadState is #[non_exhaustive]
//!             }
//!         }
//!         Ok(())
//!     });
//! # }
//! ```

/// Whether the capture pipeline is keeping up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OverloadState {
    /// Drop rate is within budget.
    #[default]
    Normal,
    /// Drop rate has crossed `enter_drop_rate` — the kernel ring is shedding
    /// faster than userspace drains it.
    Emergency,
}

/// Hysteresis thresholds for [`OverloadDetector`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct OverloadConfig {
    /// Enter [`OverloadState::Emergency`] when the windowed drop rate reaches
    /// this fraction (`0.0..=1.0`). Default `0.05` (5 %).
    pub enter_drop_rate: f64,
    /// Only leave `Emergency` once the drop rate is **below** this for
    /// `recover_windows` samples. Should be `< enter_drop_rate` for hysteresis.
    /// Default `0.01` (1 %).
    pub recover_drop_rate: f64,
    /// Consecutive sub-`recover_drop_rate` samples required to recover. Default
    /// `3` — one calm window isn't enough to declare the storm over.
    pub recover_windows: u32,
}

impl Default for OverloadConfig {
    fn default() -> Self {
        Self {
            enter_drop_rate: 0.05,
            recover_drop_rate: 0.01,
            recover_windows: 3,
        }
    }
}

impl OverloadConfig {
    /// Set the enter threshold (fraction `0.0..=1.0`).
    pub fn enter_at(mut self, drop_rate: f64) -> Self {
        self.enter_drop_rate = drop_rate;
        self
    }
    /// Set the recover threshold + the number of calm windows required.
    pub fn recover_at(mut self, drop_rate: f64, windows: u32) -> Self {
        self.recover_drop_rate = drop_rate;
        self.recover_windows = windows.max(1);
        self
    }
}

/// A hysteresis state machine over the windowed drop rate. Feed it each
/// telemetry sample's `drop_rate` via [`observe`](Self::observe).
#[derive(Debug, Clone)]
pub struct OverloadDetector {
    config: OverloadConfig,
    state: OverloadState,
    /// Consecutive samples below `recover_drop_rate` while in `Emergency`.
    calm_windows: u32,
}

impl OverloadDetector {
    /// New detector in [`OverloadState::Normal`].
    pub fn new(config: OverloadConfig) -> Self {
        Self {
            config,
            state: OverloadState::Normal,
            calm_windows: 0,
        }
    }

    /// The current state.
    pub fn state(&self) -> OverloadState {
        self.state
    }

    /// Observe one windowed `drop_rate` sample. Returns `Some(new_state)` only
    /// when the state **transitions** (so a caller can act on edges), `None`
    /// while it holds steady.
    pub fn observe(&mut self, drop_rate: f64) -> Option<OverloadState> {
        match self.state {
            OverloadState::Normal => {
                if drop_rate >= self.config.enter_drop_rate {
                    self.state = OverloadState::Emergency;
                    self.calm_windows = 0;
                    return Some(OverloadState::Emergency);
                }
                None
            }
            OverloadState::Emergency => {
                if drop_rate < self.config.recover_drop_rate {
                    self.calm_windows += 1;
                    if self.calm_windows >= self.config.recover_windows {
                        self.state = OverloadState::Normal;
                        self.calm_windows = 0;
                        return Some(OverloadState::Normal);
                    }
                } else {
                    // A sample at/above the recover floor restarts the calm count.
                    self.calm_windows = 0;
                }
                None
            }
        }
    }
}

// ── Action half (issue #54): load-shedding policy ────────────────────────────
//
// The detector above is the *signal*; this is the userspace *lever*. The
// capture pipeline has no upstream backpressure — the kernel ring tail-drops on
// its own once userspace falls behind — so the honest thing netring can do under
// overload is **reduce its own downstream work deterministically and count it**,
// shedding at the dispatch boundary (skip L7 parsing / drop new flows) rather
// than pretending it can throttle the NIC.
//
// Boundary (per #54): netring owns the *mechanism + policy enum + honest
// counters*; the *heuristic* (which flows are elephants, what rate to keep) is
// the app's. The kernel-ring `Block`/`DropOldest`/`DropNewest` levers and the
// XDP elephant-flow **shunt** (Suricata `bypass`) need the eBPF pre-filter map
// (#44) and a real NIC — they are the hardware-gated follow-up, not this
// cap-free userspace half.

/// What to do at the **dispatch boundary** while
/// [`OverloadState::Emergency`] holds. The decision is applied per *new* flow
/// (already-admitted flows keep flowing — the elephant-friendly choice), so a
/// flow's fate is stable for its whole lifetime.
///
/// `#[non_exhaustive]` — the XDP elephant-shunt (#44) will add a variant.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub enum ShedPolicy {
    /// Never shed — detect + count only (the safe default; identical
    /// admission to no shedder at all).
    #[default]
    Observe,
    /// Under `Emergency`, admit **no** new flows — process only flows already
    /// being tracked. The extreme of [`SampleFlows`](Self::SampleFlows) with
    /// `keep == 0.0`.
    ShedNewFlows,
    /// Under `Emergency`, admit a deterministic `keep` fraction (`0.0..=1.0`) of
    /// new flows by flow-hash, shedding the rest. Deterministic in the hash, so
    /// a bidirectional key keeps **both** legs of an admitted flow (pass a
    /// direction-invariant hash). `keep` is clamped to `0.0..=1.0`.
    SampleFlows {
        /// Fraction of new flows to admit while shedding.
        keep: f64,
    },
}

/// Honest shedding accounting (ties to the drop-accounting work, #39). Counts
/// admission decisions made by [`LoadShedder::admit_new_flow`] — `shed` is the
/// number of new flows the policy deliberately dropped at the dispatch
/// boundary, never silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SheddingStats {
    /// New flows admitted for full processing.
    pub admitted: u64,
    /// New flows deliberately shed by the active [`ShedPolicy`].
    pub shed: u64,
}

/// The outcome of an [`admit_new_flow`](LoadShedder::admit_new_flow) call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShedDecision {
    /// Process this flow normally.
    Admit,
    /// Drop this flow at the dispatch boundary (skip L7 parsing / handlers).
    Shed,
}

impl ShedDecision {
    /// `true` if the flow should be processed.
    pub fn is_admitted(self) -> bool {
        matches!(self, ShedDecision::Admit)
    }
    /// `true` if the flow was shed.
    pub fn is_shed(self) -> bool {
        matches!(self, ShedDecision::Shed)
    }
}

/// Couples an [`OverloadDetector`] with a [`ShedPolicy`] + honest
/// [`SheddingStats`] — the **action half** of #54. Feed it telemetry drop rates
/// via [`observe`](Self::observe); ask it
/// [`admit_new_flow`](Self::admit_new_flow) when a flow starts.
///
/// Mechanism only — the app supplies the *heuristic* (the `keep` rate, which
/// flow hash). netring guarantees deliberate, **counted** shedding.
///
/// ```no_run
/// # #[cfg(all(feature = "flow", feature = "tokio"))] fn demo() {
/// use std::sync::{Arc, Mutex};
/// use std::time::Duration;
/// use netring::monitor::Monitor;
/// use netring::monitor::overload::{LoadShedder, OverloadConfig, ShedPolicy};
/// use netring::prelude::*;
///
/// // Under overload, admit only ~25 % of *new* TCP flows (deterministic by
/// // bidirectional key hash, so both directions of a kept flow survive).
/// let shedder = Arc::new(Mutex::new(LoadShedder::new(
///     OverloadConfig::default(),
///     ShedPolicy::SampleFlows { keep: 0.25 },
/// )));
///
/// let s_stats = shedder.clone();
/// Monitor::builder()
///     .interface("eth0")
///     .protocol::<Tcp>()
///     .on_capture_stats(Duration::from_secs(1), {
///         let shedder = shedder.clone();
///         move |t, _ctx| {
///             shedder.lock().unwrap().observe(t.drop_rate);
///             Ok(())
///         }
///     })
///     .on_ctx::<FlowStarted<Tcp>>(move |evt: &FlowStarted<Tcp>, _ctx: &mut Ctx<'_>| {
///         // Hash the (bidirectional) key — canonicalized by address order, so
///         // both legs of a flow hash identically and share one admission verdict.
///         use std::hash::{Hash, Hasher};
///         let mut hasher = std::collections::hash_map::DefaultHasher::new();
///         evt.key.hash(&mut hasher);
///         if s_stats.lock().unwrap().admit_new_flow(hasher.finish()).is_shed() {
///             // skip this flow's expensive processing
///         }
///         Ok(())
///     });
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct LoadShedder {
    detector: OverloadDetector,
    policy: ShedPolicy,
    stats: SheddingStats,
}

impl LoadShedder {
    /// New shedder with the given detection thresholds + policy, starting in
    /// [`OverloadState::Normal`] with zeroed [`SheddingStats`].
    pub fn new(config: OverloadConfig, policy: ShedPolicy) -> Self {
        Self {
            detector: OverloadDetector::new(config),
            policy,
            stats: SheddingStats::default(),
        }
    }

    /// Feed one windowed `drop_rate` sample to the inner detector. Returns
    /// `Some(new_state)` on a state **transition** (see
    /// [`OverloadDetector::observe`]).
    pub fn observe(&mut self, drop_rate: f64) -> Option<OverloadState> {
        self.detector.observe(drop_rate)
    }

    /// The current overload state.
    pub fn state(&self) -> OverloadState {
        self.detector.state()
    }

    /// The active policy.
    pub fn policy(&self) -> ShedPolicy {
        self.policy
    }

    /// Snapshot of the admission counters.
    pub fn stats(&self) -> SheddingStats {
        self.stats
    }

    /// `true` when the shedder is *actively* shedding — i.e. in `Emergency`
    /// **and** the policy is not [`ShedPolicy::Observe`]. (A `SampleFlows {
    /// keep: 1.0 }` still reports `true` here even though it admits everything;
    /// it is "armed".)
    pub fn is_shedding(&self) -> bool {
        self.state() == OverloadState::Emergency && self.policy != ShedPolicy::Observe
    }

    /// Decide whether a **new** flow (identified by `flow_hash`) is admitted.
    /// Always [`Admit`](ShedDecision::Admit) in `Normal` or under
    /// [`ShedPolicy::Observe`]. The counters are updated either way.
    ///
    /// Pass a **direction-invariant** hash (e.g. a bidirectional key's hash) so
    /// both legs of a tapped/biflow conversation share one admission verdict.
    pub fn admit_new_flow(&mut self, flow_hash: u64) -> ShedDecision {
        let decision = match (self.state(), self.policy) {
            (OverloadState::Emergency, ShedPolicy::ShedNewFlows) => ShedDecision::Shed,
            (OverloadState::Emergency, ShedPolicy::SampleFlows { keep }) => {
                if unit_from_hash(flow_hash) < keep.clamp(0.0, 1.0) {
                    ShedDecision::Admit
                } else {
                    ShedDecision::Shed
                }
            }
            // Normal state, or Observe policy: never shed.
            _ => ShedDecision::Admit,
        };
        match decision {
            ShedDecision::Admit => self.stats.admitted += 1,
            ShedDecision::Shed => self.stats.shed += 1,
        }
        decision
    }
}

/// Map a 64-bit hash to a uniform `f64` in `[0.0, 1.0)` using the top 53 bits
/// (the f64 mantissa width) — a deterministic, allocation-free unit sample.
#[inline]
fn unit_from_hash(hash: u64) -> f64 {
    (hash >> 11) as f64 / ((1u64 << 53) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> OverloadDetector {
        // enter ≥ 0.05, recover < 0.01 for 3 windows.
        OverloadDetector::new(OverloadConfig::default())
    }

    #[test]
    fn stays_normal_under_budget() {
        let mut d = det();
        for r in [0.0, 0.01, 0.04, 0.049] {
            assert_eq!(d.observe(r), None);
        }
        assert_eq!(d.state(), OverloadState::Normal);
    }

    #[test]
    fn enters_emergency_on_crossing() {
        let mut d = det();
        assert_eq!(d.observe(0.06), Some(OverloadState::Emergency));
        assert_eq!(d.state(), OverloadState::Emergency);
        // No repeat transition while it stays high.
        assert_eq!(d.observe(0.20), None);
    }

    #[test]
    fn requires_sustained_calm_to_recover() {
        let mut d = det();
        d.observe(0.10); // → Emergency
        // Two calm windows aren't enough (recover_windows = 3).
        assert_eq!(d.observe(0.005), None);
        assert_eq!(d.observe(0.005), None);
        assert_eq!(d.observe(0.005), Some(OverloadState::Normal));
    }

    #[test]
    fn a_spike_resets_the_calm_counter_no_flapping() {
        let mut d = det();
        d.observe(0.10); // → Emergency
        d.observe(0.005); // calm 1
        d.observe(0.005); // calm 2
        d.observe(0.08); // spike → calm reset, still Emergency
        assert_eq!(d.state(), OverloadState::Emergency);
        // Now needs 3 fresh calm windows again.
        assert_eq!(d.observe(0.0), None);
        assert_eq!(d.observe(0.0), None);
        assert_eq!(d.observe(0.0), Some(OverloadState::Normal));
    }

    #[test]
    fn between_recover_and_enter_holds_emergency() {
        let mut d = det();
        d.observe(0.10); // → Emergency
        // 0.03 is below enter (0.05) but above recover (0.01): no recovery.
        for _ in 0..10 {
            assert_eq!(d.observe(0.03), None);
        }
        assert_eq!(d.state(), OverloadState::Emergency);
    }

    // ── action half: LoadShedder ─────────────────────────────────────────

    fn shedder(policy: ShedPolicy) -> LoadShedder {
        LoadShedder::new(OverloadConfig::default(), policy)
    }

    #[test]
    fn unit_from_hash_is_in_range_and_monotone() {
        assert_eq!(unit_from_hash(0), 0.0);
        assert!(unit_from_hash(u64::MAX) < 1.0);
        assert!(unit_from_hash(u64::MAX) > 0.999);
        assert!(unit_from_hash(1u64 << 62) > unit_from_hash(1u64 << 60));
    }

    #[test]
    fn normal_state_always_admits_regardless_of_policy() {
        for policy in [
            ShedPolicy::Observe,
            ShedPolicy::ShedNewFlows,
            ShedPolicy::SampleFlows { keep: 0.0 },
        ] {
            let mut s = shedder(policy);
            assert_eq!(s.state(), OverloadState::Normal);
            for h in 0..1000 {
                assert!(s.admit_new_flow(h).is_admitted());
            }
            assert_eq!(s.stats().shed, 0);
            assert_eq!(s.stats().admitted, 1000);
            assert!(!s.is_shedding());
        }
    }

    #[test]
    fn observe_policy_never_sheds_even_in_emergency() {
        let mut s = shedder(ShedPolicy::Observe);
        assert_eq!(s.observe(0.10), Some(OverloadState::Emergency));
        for h in 0..1000 {
            assert!(s.admit_new_flow(h).is_admitted());
        }
        assert_eq!(s.stats().shed, 0);
        assert!(!s.is_shedding(), "Observe is never actively shedding");
    }

    #[test]
    fn shed_new_flows_drops_all_new_in_emergency() {
        let mut s = shedder(ShedPolicy::ShedNewFlows);
        s.observe(0.10); // → Emergency
        assert!(s.is_shedding());
        for h in 0..500 {
            assert!(s.admit_new_flow(h).is_shed());
        }
        assert_eq!(s.stats().shed, 500);
        assert_eq!(s.stats().admitted, 0);
    }

    #[test]
    fn sample_flows_admits_roughly_keep_fraction_in_emergency() {
        let mut s = shedder(ShedPolicy::SampleFlows { keep: 0.25 });
        s.observe(0.10); // → Emergency
        // Spread hashes across the full u64 range so the unit map is uniform.
        let n = 10_000u64;
        for i in 0..n {
            let h = i.wrapping_mul(0x9E37_79B9_7F4A_7C15); // golden-ratio spread
            s.admit_new_flow(h);
        }
        let admitted = s.stats().admitted as f64 / n as f64;
        assert!(
            (admitted - 0.25).abs() < 0.03,
            "admitted fraction {admitted} should be ~0.25",
        );
    }

    #[test]
    fn sample_flows_is_deterministic_per_hash() {
        let mut a = shedder(ShedPolicy::SampleFlows { keep: 0.5 });
        let mut b = shedder(ShedPolicy::SampleFlows { keep: 0.5 });
        a.observe(0.10);
        b.observe(0.10);
        for h in 0..1000 {
            assert_eq!(
                a.admit_new_flow(h),
                b.admit_new_flow(h),
                "same hash must yield same verdict (both legs share a fate)",
            );
        }
    }

    #[test]
    fn keep_is_clamped() {
        // keep > 1.0 admits everything; keep < 0.0 sheds everything.
        let mut hi = shedder(ShedPolicy::SampleFlows { keep: 2.0 });
        hi.observe(0.10);
        let mut lo = shedder(ShedPolicy::SampleFlows { keep: -1.0 });
        lo.observe(0.10);
        for h in 0..200 {
            assert!(hi.admit_new_flow(h).is_admitted());
            assert!(lo.admit_new_flow(h).is_shed());
        }
    }

    #[test]
    fn admission_resumes_after_recovery() {
        let mut s = shedder(ShedPolicy::ShedNewFlows);
        s.observe(0.10); // → Emergency
        assert!(s.admit_new_flow(1).is_shed());
        // Recover (default needs 3 calm windows).
        s.observe(0.0);
        s.observe(0.0);
        assert_eq!(s.observe(0.0), Some(OverloadState::Normal));
        assert!(!s.is_shedding());
        assert!(s.admit_new_flow(1).is_admitted());
    }
}
