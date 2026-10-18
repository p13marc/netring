//! Suppress repeated `(kind, key)` anomalies within a sliding window.

use std::fmt::Write as _;
use std::hash::Hasher;
use std::time::Duration;

use flowscope::Timestamp;
use rustc_hash::{FxHashMap, FxHasher};

use crate::anomaly::sink::{AnomalyRecord, AnomalySink};
use crate::layer::Layer;

/// Suppress duplicate anomalies (same `kind` + same `Debug`-formatted
/// `key`) within a sliding `window`. Subsequent identical anomalies
/// within the window are dropped; once the window expires the next
/// one re-fires.
///
/// The window is measured in **packet time** — each anomaly's own
/// timestamp — so a fast [`Monitor::replay`](crate::monitor::Monitor)
/// suppresses exactly what a live run over the same traffic would, and
/// an anomaly with a timestamp before the one it repeats counts as
/// within the window.
///
/// Each `(kind, key)` pair is remembered as a 64-bit hash of `kind` and
/// the key's `Debug` text (written straight into the hasher — no `String`
/// per anomaly); entries older than the window are purged every 1024
/// insertions.
///
/// `Clone` (0.22): the dedup table lives in the per-`wrap()` sink, so
/// the config clones cleanly for [`LayerSpec`](crate::layer::LayerSpec)
/// — each shard gets its own empty table.
#[derive(Debug, Clone)]
pub struct DedupeAnomalies {
    window: Duration,
}

impl DedupeAnomalies {
    /// Suppress duplicates within `window` (of packet time).
    pub fn within(window: Duration) -> Self {
        Self { window }
    }
}

impl Layer for DedupeAnomalies {
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        Box::new(DedupeAnomaliesLayered {
            inner,
            window: self.window,
            seen: FxHashMap::default(),
            inserts: 0,
        })
    }
}

/// Entries inserted between two purges of the expired ones.
const PURGE_EVERY: u32 = 1024;

/// The applied layer — wraps an inner sink + the dedup state.
pub struct DedupeAnomaliesLayered {
    inner: Box<dyn AnomalySink>,
    window: Duration,
    /// `(kind, key)` hash → when it last fired (packet time).
    seen: FxHashMap<u64, Timestamp>,
    inserts: u32,
}

/// Hashes `Debug` output as it is written. Bytes go to the hasher in
/// fixed-size blocks, so the hash depends only on the text, not on how
/// the formatter splits it into `write_str` calls.
struct KeyHasher {
    hasher: FxHasher,
    buf: [u8; 32],
    len: usize,
}

impl KeyHasher {
    fn new() -> Self {
        Self {
            hasher: FxHasher::default(),
            buf: [0; 32],
            len: 0,
        }
    }

    fn finish(mut self) -> u64 {
        self.hasher.write(&self.buf[..self.len]);
        self.hasher.finish()
    }

    fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = (self.buf.len() - self.len).min(bytes.len());
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
            bytes = &bytes[n..];
            if self.len == self.buf.len() {
                self.hasher.write(&self.buf);
                self.len = 0;
            }
        }
    }
}

impl std::fmt::Write for KeyHasher {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

/// The dedup identity of an anomaly: `kind`, then the key's `Debug` text —
/// or, for a record without a key (an owned anomaly published with
/// `publish_owned`, endpoints set by hand), its endpoints: two such
/// anomalies about different flows are not duplicates.
fn dedupe_hash(
    kind: &'static str,
    key: Option<&dyn crate::anomaly::Key>,
    endpoints: Option<&crate::anomaly::sink::Endpoints>,
) -> u64 {
    let mut h = KeyHasher::new();
    h.push(kind.as_bytes());
    // A separator byte no `&str` contains: `kind` "ab" + key "c" must not
    // hash like `kind` "a" + key "bc".
    h.push(&[0xff]);
    match (key, endpoints) {
        (Some(k), _) => {
            let _ = write!(h, "{k:?}");
        }
        (None, Some(e)) => {
            h.push(&[0xfe]);
            let _ = write!(h, "{e:?}");
        }
        (None, None) => {}
    }
    h.finish()
}

/// How far apart two packet timestamps are, either way round. A repeat
/// stamped *earlier* than the one remembered (several capture queues, a
/// merged replay) is within the window only if it is that close — a clock
/// that stepped back by more than the window starts afresh instead of
/// suppressing the key until the clock catches up.
pub(crate) fn distance(a: Timestamp, b: Timestamp) -> Duration {
    a.saturating_sub(b).max(b.saturating_sub(a))
}

impl AnomalySink for DedupeAnomaliesLayered {
    fn write(&mut self, record: &AnomalyRecord<'_>) {
        let (kind, ts) = (record.kind, record.ts);
        let id = dedupe_hash(kind, record.key, record.endpoints.as_ref());
        if let Some(prev) = self.seen.get(&id)
            && distance(ts, *prev) < self.window
        {
            return;
        }
        self.seen.insert(id, ts);
        // Purge expired entries now and then, to bound the table in
        // long-running monitors.
        self.inserts += 1;
        if self.inserts >= PURGE_EVERY {
            self.inserts = 0;
            let window = self.window;
            self.seen.retain(|_, last| distance(ts, *last) < window);
        }
        self.inner.write(record);
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::Severity;

    #[derive(Default)]
    struct Capture(Arc<Mutex<Vec<&'static str>>>);
    impl Capture {
        fn list(&self) -> Arc<Mutex<Vec<&'static str>>> {
            Arc::clone(&self.0)
        }
    }
    impl AnomalySink for Capture {
        fn write(&mut self, record: &AnomalyRecord<'_>) {
            let kind = record.kind;
            self.0.lock().unwrap().push(kind);
        }
    }

    #[test]
    fn second_within_window_is_dropped() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_secs(10))).wrap(Box::new(inner));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        let calls = calls.lock().unwrap();
        assert_eq!(*calls, vec!["X"]);
    }

    #[test]
    fn different_keys_not_deduped() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_secs(10))).wrap(Box::new(inner));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&2u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&3u32)
            .emit();
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    /// The window is packet time: a repeat a nanosecond short of it is
    /// dropped, one a full window later fires again.
    #[test]
    fn after_window_expiry_dup_passes_again() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_millis(10))).wrap(Box::new(inner));
        for ts in [
            Timestamp::new(5, 0),
            Timestamp::new(5, 9_999_999),
            Timestamp::new(5, 10_000_000),
        ] {
            sink.begin("X", Severity::Info, ts).with_key(&1u32).emit();
        }
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    /// Review r2: after the clock steps back by more than the window, the
    /// key isn't suppressed until the clock catches up — the step starts
    /// afresh; a repeat right after it is still a duplicate.
    #[test]
    fn a_backward_clock_step_does_not_suppress_for_the_whole_step() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_millis(10))).wrap(Box::new(inner));
        for ts in [
            Timestamp::new(1_000, 0),
            Timestamp::new(10, 0),
            Timestamp::new(10, 1_000_000),
            // A small reorder within the window is still a duplicate.
            Timestamp::new(9, 999_000_000),
        ] {
            sink.begin("X", Severity::Info, ts).with_key(&1u32).emit();
        }
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    /// Review r3: anomalies without a key — an owned anomaly published
    /// with `publish_owned` — about different flows are not duplicates of
    /// each other; the same flow's are.
    #[test]
    fn keyless_records_dedupe_by_their_endpoints() {
        use crate::anomaly::sink::{AnomalyRecord, Endpoints};
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_secs(10))).wrap(Box::new(inner));
        let flow = |port: u16| {
            Endpoints::new(
                format!("10.0.0.9:{port}").parse().unwrap(),
                "10.0.0.1:53".parse().unwrap(),
                Some("UDP"),
                false,
            )
        };
        for e in [flow(40_000), flow(40_001), flow(40_000)] {
            sink.write(
                &AnomalyRecord::new("Dga", Severity::Info, Timestamp::new(1, 0)).with_endpoints(e),
            );
        }
        assert_eq!(*calls.lock().unwrap(), vec!["Dga", "Dga"]);
    }

    /// The same kind and key text dedupe together, whatever splits the
    /// text into `write_str` calls; a different kind doesn't.
    #[test]
    fn hash_follows_the_text_not_its_chunks() {
        struct Chunked(&'static [&'static str]);
        impl std::fmt::Debug for Chunked {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.iter().try_for_each(|s| f.write_str(s))
            }
        }
        let long = "a key long enough to span more than one 32-byte block";
        let one = Chunked(&["a key long enough to span more than one 32-byte block"]);
        let many = Chunked(&[
            "a key l",
            "ong enough to span more than",
            " one 32-byte block",
        ]);
        assert_eq!(format!("{one:?}"), long);
        assert_eq!(
            dedupe_hash("K", Some(&one as &dyn crate::anomaly::Key), None),
            dedupe_hash("K", Some(&many as &dyn crate::anomaly::Key), None)
        );
        assert_ne!(
            dedupe_hash("K", Some(&one as &dyn crate::anomaly::Key), None),
            dedupe_hash("L", Some(&one as &dyn crate::anomaly::Key), None)
        );
        // `kind` "ab" + key "c" is not `kind` "a" + key "bc".
        assert_ne!(
            dedupe_hash(
                "ab",
                Some(&Chunked(&["c"]) as &dyn crate::anomaly::Key),
                None
            ),
            dedupe_hash(
                "a",
                Some(&Chunked(&["bc"]) as &dyn crate::anomaly::Key),
                None
            )
        );
    }

    /// Expired entries are purged every 1024 insertions, so the table
    /// stays bounded on a long run of distinct keys.
    #[test]
    fn expired_entries_are_purged() {
        let mut sink = DedupeAnomaliesLayered {
            inner: Box::new(Capture::default()),
            window: Duration::from_secs(1),
            seen: FxHashMap::default(),
            inserts: 0,
        };
        for i in 0..5_000u32 {
            // One distinct key per millisecond: at most ~1000 within a window.
            let ts = Timestamp::new(i / 1000, (i % 1000) * 1_000_000);
            sink.write(&AnomalyRecord::new("X", Severity::Info, ts).with_key(&i));
        }
        assert!(
            sink.seen.len() <= 2 * PURGE_EVERY as usize,
            "{}",
            sink.seen.len()
        );
    }

    #[test]
    fn no_key_dedups_by_kind_only() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_secs(10))).wrap(Box::new(inner));
        sink.begin("Y", Severity::Info, Timestamp::new(0, 0)).emit();
        sink.begin("Y", Severity::Info, Timestamp::new(0, 0)).emit();
        assert_eq!(calls.lock().unwrap().len(), 1);
    }
}
