//! Busy-poll trio configuration for AF_PACKET captures.
//!
//! Set via the builder methods
//! [`CaptureBuilder::busy_poll_us`](crate::CaptureBuilder::busy_poll_us),
//! [`prefer_busy_poll`](crate::CaptureBuilder::prefer_busy_poll), and
//! [`busy_poll_budget`](crate::CaptureBuilder::busy_poll_budget). Inspect
//! the applied trio on a built [`Capture`](crate::Capture) via
//! [`busy_poll_config`](crate::Capture::busy_poll_config).
//!
//! When at least one knob is set at build time, netring emits a
//! `tracing::info!` with target `"netring::capture::busy_poll"` so the
//! operator can confirm the trio engaged on the captured socket.

/// Busy-poll trio applied to the capture socket. Empty by default
/// (no busy-polling).
///
/// Each field is independently optional — set only the knobs you
/// care about; unset ones keep kernel defaults. Use
/// [`is_active`](Self::is_active) to check whether any knob is in
/// effect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BusyPollConfig {
    /// `SO_BUSY_POLL` value in microseconds (kernel ≥ 3.11).
    pub busy_poll_us: Option<u32>,
    /// `SO_PREFER_BUSY_POLL` toggle (kernel ≥ 5.11).
    pub prefer_busy_poll: Option<bool>,
    /// `SO_BUSY_POLL_BUDGET` packet count (kernel ≥ 5.11).
    pub busy_poll_budget: Option<u16>,
}

impl BusyPollConfig {
    /// True if any of the three knobs is set.
    pub fn is_active(&self) -> bool {
        self.busy_poll_us.is_some()
            || self.prefer_busy_poll.is_some()
            || self.busy_poll_budget.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_inactive() {
        assert!(!BusyPollConfig::default().is_active());
    }

    #[test]
    fn any_single_knob_activates() {
        let cfg = BusyPollConfig {
            busy_poll_us: Some(50),
            ..Default::default()
        };
        assert!(cfg.is_active());

        let cfg = BusyPollConfig {
            prefer_busy_poll: Some(true),
            ..Default::default()
        };
        assert!(cfg.is_active());

        let cfg = BusyPollConfig {
            busy_poll_budget: Some(64),
            ..Default::default()
        };
        assert!(cfg.is_active());
    }

    #[test]
    fn all_three_active() {
        let cfg = BusyPollConfig {
            busy_poll_us: Some(50),
            prefer_busy_poll: Some(true),
            busy_poll_budget: Some(64),
        };
        assert!(cfg.is_active());
    }
}
