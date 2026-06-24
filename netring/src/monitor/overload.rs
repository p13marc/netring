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
}
