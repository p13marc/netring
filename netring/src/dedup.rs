//! Loopback / content-hash packet deduplication.
//!
//! When you `tcpdump -i lo` (or netring's equivalent on `lo`), the
//! Linux kernel re-injects every outgoing packet as incoming, so
//! every "logical" packet appears at least twice. The same can
//! happen on bridged interfaces and some switch monitor ports. This
//! module filters those duplicates.
//!
//! # Modes
//!
//! - [`Dedup::loopback`] — tuned for `lo`. 1ms window, 256-entry
//!   ring, **direction-aware**: only drops when one packet was
//!   `Outgoing` and its twin was `Host` (or vice versa) within the
//!   window. Same-direction repeats (legitimate retransmits) are
//!   kept.
//! - [`Dedup::content`] — generic content-hash dedup. Configurable
//!   window + ring size. Direction-agnostic. Use for any
//!   capture path that delivers duplicates.
//!
//! # Cost
//!
//! ~100 ns per packet (xxh3-64 hash + linear scan of a small ring).
//! ~6 KiB of memory per `Dedup` instance.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! use futures::StreamExt;
//! use netring::{AsyncCapture, Dedup};
//!
//! let cap = AsyncCapture::open("lo")?;
//! let mut stream = cap.dedup_stream(Dedup::loopback());
//! while let Some(pkt) = stream.next().await {
//!     let _pkt = pkt?;
//!     # break;
//! }
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use crate::packet::{Packet, PacketDirection, Timestamp};

/// Drop duplicate packets from a capture stream.
///
/// See module-level docs.
pub struct Dedup {
    ring: Vec<Option<Entry>>,
    head: usize,
    window: Duration,
    direction_aware: bool,
    dropped: u64,
    seen: u64,
}

#[derive(Clone, Copy)]
struct Entry {
    hash: u64,
    len: u32,
    /// Total nanoseconds since UNIX epoch — easier to subtract than
    /// (sec, nsec) pairs.
    ts_ns: u128,
    direction: PacketDirection,
}

impl Dedup {
    /// Configured for loopback: 1ms window, 256-entry ring,
    /// direction-aware (Outgoing/Host matching enabled).
    ///
    /// Drops the duplicate copy that the kernel re-injects when
    /// capturing on `lo`. Keeps each logical packet exactly once.
    pub fn loopback() -> Self {
        Self::new(Duration::from_millis(1), 256, true)
    }

    /// Generic content-hash dedup with the given window and ring size.
    /// Direction-agnostic — use for any capture path that delivers
    /// duplicates that aren't loopback's outgoing/host pair (e.g.,
    /// bridged interfaces, switch monitor ports, double-tagged
    /// VLAN observation).
    ///
    /// Pick a `window` that's longer than the largest expected
    /// duplicate gap but shorter than legitimate retransmit
    /// intervals. 5–50 ms is reasonable for most non-`lo` cases.
    pub fn content(window: Duration, ring_size: usize) -> Self {
        Self::new(window, ring_size, false)
    }

    /// Custom config — explicit knobs.
    pub fn new(window: Duration, ring_size: usize, direction_aware: bool) -> Self {
        let ring_size = ring_size.max(1);
        Self {
            ring: vec![None; ring_size],
            head: 0,
            window,
            direction_aware,
            dropped: 0,
            seen: 0,
        }
    }

    /// Decide whether to keep `pkt`.
    ///
    /// Returns `true` to keep, `false` to drop. Updates internal
    /// state regardless. Cheap (~100 ns).
    pub fn keep(&mut self, pkt: &Packet<'_>) -> bool {
        self.keep_raw(pkt.data(), pkt.direction(), pkt.timestamp())
    }

    /// Same logic but operating on (data, direction, timestamp)
    /// directly. Useful for pcap-replay or synthetic-frame use
    /// where you don't have a `Packet`.
    pub fn keep_raw(&mut self, data: &[u8], direction: PacketDirection, ts: Timestamp) -> bool {
        self.seen += 1;
        let hash = xxhash_rust::xxh3::xxh3_64(data);
        let len = data.len() as u32;
        let ts_ns = (ts.sec as u128) * 1_000_000_000 + (ts.nsec as u128);
        let window_ns = self.window.as_nanos();

        // Scan the ring for a recent matching entry.
        for slot in &self.ring {
            let Some(e) = slot else { continue };
            if e.hash != hash || e.len != len {
                continue;
            }
            // ts_ns may go backwards by a few microseconds across
            // ring frames; saturating subtraction avoids treating
            // those as "from the future."
            let elapsed = ts_ns.saturating_sub(e.ts_ns);
            if elapsed > window_ns {
                continue;
            }
            // Hash + len match within the window.
            if !self.direction_aware {
                self.dropped += 1;
                return false;
            }
            if directions_complementary(e.direction, direction) {
                self.dropped += 1;
                return false;
            }
            // Same direction in direction-aware mode: legitimate
            // retransmit (or capture-side artifact). Keep.
        }

        // Insert new entry, advancing the ring head.
        self.ring[self.head] = Some(Entry {
            hash,
            len,
            ts_ns,
            direction,
        });
        self.head = (self.head + 1) % self.ring.len();
        true
    }

    /// Total packets dropped as duplicates since construction.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Total packets seen (kept + dropped).
    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// Reset all counters and the ring buffer.
    pub fn reset(&mut self) {
        for slot in &mut self.ring {
            *slot = None;
        }
        self.head = 0;
        self.dropped = 0;
        self.seen = 0;
    }
}

/// Loopback re-injection always pairs `Outgoing` with `Host`. Other
/// PacketDirection values are not part of the kernel's lo
/// duplicate semantics, so we treat them as non-complementary.
fn directions_complementary(a: PacketDirection, b: PacketDirection) -> bool {
    matches!(
        (a, b),
        (PacketDirection::Outgoing, PacketDirection::Host)
            | (PacketDirection::Host, PacketDirection::Outgoing)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(sec: u32, nsec: u32) -> Timestamp {
        Timestamp::new(sec, nsec)
    }

    #[test]
    fn loopback_drops_outgoing_then_host_within_window() {
        let mut d = Dedup::loopback();
        // Outgoing first
        assert!(d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 0)));
        // Host echo 100 µs later — should be dropped
        assert!(!d.keep_raw(b"abc", PacketDirection::Host, ts(0, 100_000)));
        assert_eq!(d.dropped(), 1);
        assert_eq!(d.seen(), 2);
    }

    #[test]
    fn loopback_keeps_outside_window() {
        let mut d = Dedup::loopback();
        assert!(d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 0)));
        // 2 ms later — past the 1 ms window
        assert!(d.keep_raw(b"abc", PacketDirection::Host, ts(0, 2_000_000)));
        assert_eq!(d.dropped(), 0);
    }

    #[test]
    fn loopback_keeps_same_direction_repeats() {
        let mut d = Dedup::loopback();
        assert!(d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 0)));
        // Same direction within window: legitimate retransmit
        assert!(d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 100_000)));
        assert_eq!(d.dropped(), 0);
    }

    #[test]
    fn content_drops_same_hash_regardless_of_direction() {
        let mut d = Dedup::content(Duration::from_millis(5), 64);
        assert!(d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 0)));
        // Same direction — direction-agnostic mode still drops it
        assert!(!d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 100_000)));
        assert_eq!(d.dropped(), 1);
    }

    #[test]
    fn ring_overflow_evicts_oldest() {
        let mut d = Dedup::content(Duration::from_secs(1), 4);
        // Fill the ring with 4 distinct packets
        for i in 0..4u8 {
            assert!(d.keep_raw(&[i], PacketDirection::Host, ts(0, 0)));
        }
        // Insert a 5th — evicts the oldest [0]
        assert!(d.keep_raw(&[4], PacketDirection::Host, ts(0, 0)));
        // Re-feed [0] — should be kept (its ring entry was evicted)
        assert!(d.keep_raw(&[0], PacketDirection::Host, ts(0, 0)));
        // Re-feed [4] — should be dropped (still in ring)
        assert!(!d.keep_raw(&[4], PacketDirection::Host, ts(0, 0)));
    }

    #[test]
    fn different_lengths_dont_match_even_on_hash_collision() {
        // Length is part of the match key, so even a hash collision
        // requires same-length packets to be flagged as duplicates.
        let mut d = Dedup::content(Duration::from_secs(1), 64);
        assert!(d.keep_raw(b"abc", PacketDirection::Host, ts(0, 0)));
        // Different content + length → different hash + len → keep
        assert!(d.keep_raw(b"abcd", PacketDirection::Host, ts(0, 0)));
        assert_eq!(d.dropped(), 0);
    }

    #[test]
    fn reset_clears_state() {
        let mut d = Dedup::loopback();
        d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 0));
        d.keep_raw(b"abc", PacketDirection::Host, ts(0, 100_000));
        assert_eq!(d.dropped(), 1);
        d.reset();
        assert_eq!(d.dropped(), 0);
        assert_eq!(d.seen(), 0);
        // After reset, the same sequence should re-trigger
        assert!(d.keep_raw(b"abc", PacketDirection::Outgoing, ts(0, 0)));
        assert!(!d.keep_raw(b"abc", PacketDirection::Host, ts(0, 100_000)));
    }

    #[test]
    fn empty_payload_handled() {
        let mut d = Dedup::loopback();
        assert!(d.keep_raw(b"", PacketDirection::Outgoing, ts(0, 0)));
        assert!(!d.keep_raw(b"", PacketDirection::Host, ts(0, 1_000)));
    }

    #[test]
    fn directions_complementary_table() {
        use PacketDirection::*;
        assert!(directions_complementary(Outgoing, Host));
        assert!(directions_complementary(Host, Outgoing));
        assert!(!directions_complementary(Host, Host));
        assert!(!directions_complementary(Outgoing, Outgoing));
        assert!(!directions_complementary(Broadcast, Outgoing));
        assert!(!directions_complementary(Outgoing, Multicast));
    }

    #[test]
    fn timestamp_clock_skew_doesnt_break() {
        // ts can go backwards a tiny amount across kernel ring frames.
        // Saturating subtraction prevents a "future" timestamp from
        // wrongly extending the window.
        let mut d = Dedup::loopback();
        assert!(d.keep_raw(b"abc", PacketDirection::Outgoing, ts(1, 0)));
        // "Earlier" timestamp — must still be considered within the window
        assert!(!d.keep_raw(b"abc", PacketDirection::Host, ts(0, 999_999_999)));
    }
}
