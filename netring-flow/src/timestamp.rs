//! Nanosecond-precision timestamp shared across the netring family.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Nanosecond-precision kernel timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    /// Seconds since epoch.
    pub sec: u32,
    /// Nanoseconds within the second.
    pub nsec: u32,
}

impl Timestamp {
    /// Create a new timestamp.
    #[inline]
    pub const fn new(sec: u32, nsec: u32) -> Self {
        Self { sec, nsec }
    }

    /// Convert to [`SystemTime`].
    #[inline]
    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.sec as u64, self.nsec)
    }

    /// Convert to [`Duration`] since epoch.
    #[inline]
    pub fn to_duration(self) -> Duration {
        Duration::new(self.sec as u64, self.nsec)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(ts: Timestamp) -> Self {
        ts.to_system_time()
    }
}

impl From<Timestamp> for Duration {
    fn from(ts: Timestamp) -> Self {
        ts.to_duration()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:09}", self.sec, self.nsec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_new() {
        let ts = Timestamp::new(1234, 567890);
        assert_eq!(ts.sec, 1234);
        assert_eq!(ts.nsec, 567890);
    }

    #[test]
    fn timestamp_to_system_time() {
        let ts = Timestamp::new(1_000_000_000, 500_000_000);
        let st = ts.to_system_time();
        let expected = UNIX_EPOCH + Duration::new(1_000_000_000, 500_000_000);
        assert_eq!(st, expected);
    }

    #[test]
    fn timestamp_to_duration() {
        let ts = Timestamp::new(5, 123456789);
        let d = ts.to_duration();
        assert_eq!(d, Duration::new(5, 123456789));
    }

    #[test]
    fn timestamp_display() {
        let ts = Timestamp::new(1234, 1);
        assert_eq!(ts.to_string(), "1234.000000001");
    }

    #[test]
    fn timestamp_ordering() {
        let a = Timestamp::new(1, 0);
        let b = Timestamp::new(1, 1);
        let c = Timestamp::new(2, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn timestamp_default_is_zero() {
        let ts = Timestamp::default();
        assert_eq!(ts.sec, 0);
        assert_eq!(ts.nsec, 0);
    }
}
