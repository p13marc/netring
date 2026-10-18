//! The packet clock of the suppression layers ([`DedupeAnomalies`],
//! [`RateLimitAnomalies`]).
//!
//! Anomalies carry their packet's timestamp, and one Monitor can see
//! several clocks at once: capture queues or NICs whose clocks disagree
//! (one on a PHC in TAI, another on system time, 37 s apart), records
//! interleaved. A window measured on each record's own timestamp then
//! jumps back and forth between the clocks and never holds. So the
//! layers read time as the **high-water mark** of the timestamps seen: an
//! earlier-stamped record reads as that. Only when the timestamps stay
//! behind for good — a real clock step back — does the clock follow them:
//! once consecutive records more than a window behind have advanced a
//! window of their own time. Until then a step back is bounded by the
//! window it lands in.
//!
//! [`DedupeAnomalies`]: crate::layer::DedupeAnomalies
//! [`RateLimitAnomalies`]: crate::layer::RateLimitAnomalies

use std::time::Duration;

use flowscope::Timestamp;

/// A [`SteadyClock`]'s time for one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reading {
    /// The high-water mark of the timestamps seen (this one included).
    Now(Timestamp),
    /// The timestamps stepped back for good and the clock restarted at
    /// this one: state measured on the old clock must be dropped.
    Restarted(Timestamp),
}

/// See the module docs.
#[derive(Debug, Default)]
pub(crate) struct SteadyClock {
    high: Option<Timestamp>,
    /// The first of the current run of consecutive records stamped more
    /// than a span before `high`.
    behind_since: Option<Timestamp>,
}

impl SteadyClock {
    /// Read the clock for a record stamped `ts`; `span` is the layer's
    /// window: how far behind counts as another clock, and how long the
    /// earlier clock must persist to be followed.
    pub(crate) fn read(&mut self, ts: Timestamp, span: Duration) -> Reading {
        let Some(high) = self.high else {
            self.high = Some(ts);
            return Reading::Now(ts);
        };
        if ts >= high || high.saturating_sub(ts) < span {
            // On the clock, or slightly reordered.
            self.behind_since = None;
            let now = ts.max(high);
            self.high = Some(now);
            return Reading::Now(now);
        }
        match self.behind_since {
            Some(since) if ts.saturating_sub(since) >= span => {
                self.high = Some(ts);
                self.behind_since = None;
                Reading::Restarted(ts)
            }
            Some(_) => Reading::Now(high),
            None => {
                self.behind_since = Some(ts);
                Reading::Now(high)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPAN: Duration = Duration::from_secs(1);

    fn at(ms: u64) -> Timestamp {
        Timestamp::new((ms / 1000) as u32, ((ms % 1000) * 1_000_000) as u32)
    }

    #[test]
    fn interleaved_clocks_read_as_the_later_one() {
        let mut c = SteadyClock::default();
        for i in 0..100 {
            let t = i * 10;
            assert_eq!(c.read(at(37_000 + t), SPAN), Reading::Now(at(37_000 + t)));
            // The other clock, 37 s behind: read as the later one.
            assert_eq!(c.read(at(t + 5), SPAN), Reading::Now(at(37_000 + t)));
        }
    }

    #[test]
    fn a_step_back_is_followed_once_it_persists_for_a_span() {
        let mut c = SteadyClock::default();
        c.read(at(100_000), SPAN);
        // The clock steps back 90 s: read as the old time for a span…
        assert_eq!(c.read(at(10_000), SPAN), Reading::Now(at(100_000)));
        assert_eq!(c.read(at(10_500), SPAN), Reading::Now(at(100_000)));
        // …then followed.
        assert_eq!(c.read(at(11_000), SPAN), Reading::Restarted(at(11_000)));
        assert_eq!(c.read(at(11_100), SPAN), Reading::Now(at(11_100)));
        // A record on the old clock in between restarts the count.
        let mut c = SteadyClock::default();
        c.read(at(100_000), SPAN);
        c.read(at(10_000), SPAN);
        c.read(at(100_001), SPAN);
        assert_eq!(c.read(at(11_000), SPAN), Reading::Now(at(100_001)));
    }

    #[test]
    fn small_reorders_are_on_the_clock() {
        let mut c = SteadyClock::default();
        c.read(at(5_000), SPAN);
        assert_eq!(c.read(at(4_500), SPAN), Reading::Now(at(5_000)));
        assert_eq!(c.read(at(5_200), SPAN), Reading::Now(at(5_200)));
    }
}
