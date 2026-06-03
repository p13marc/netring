//! [`AnomalyMonitor`] — fan an event into N [`AnomalyRule`]s.

use flowscope::Timestamp;

use super::rule::{Anomaly, AnomalyRule};
use crate::protocol::ProtocolEvent;

/// Composes one or more [`AnomalyRule`]s into a single observer
/// over a [`ProtocolEvent`] stream.
///
/// Owns a reusable scratch `Vec<Anomaly<K>>` so each call to
/// [`observe`](Self::observe) / [`on_tick`](Self::on_tick) doesn't
/// re-allocate when rules emit nothing — the typical case.
pub struct AnomalyMonitor<K> {
    rules: Vec<Box<dyn AnomalyRule<K> + Send>>,
    scratch: Vec<Anomaly<K>>,
}

impl<K> Default for AnomalyMonitor<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> AnomalyMonitor<K> {
    /// Empty monitor — start adding rules via [`with_rule`](Self::with_rule)
    /// or [`add_rule`](Self::add_rule).
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            scratch: Vec::new(),
        }
    }

    /// Builder-style add — consumes and returns `self`.
    pub fn with_rule<R: AnomalyRule<K> + 'static>(mut self, rule: R) -> Self {
        self.add_rule(rule);
        self
    }

    /// In-place add — for cases where the rule set is computed
    /// dynamically. The `Box<dyn ..>` allocation matches the static
    /// `with_rule` form.
    pub fn add_rule<R: AnomalyRule<K> + 'static>(&mut self, rule: R) {
        self.rules.push(Box::new(rule));
    }

    /// Number of rules registered.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Rule names in insertion order — useful for logging /
    /// metrics setup.
    pub fn rule_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.rules.iter().map(|r| r.name())
    }

    /// Push `evt` through every registered rule and return any
    /// resulting anomalies. The returned `Vec` is freshly
    /// allocated each call so the caller can keep it without
    /// fighting the borrow checker; the internal scratch buffer
    /// is left empty for the next call.
    pub fn observe(&mut self, evt: &ProtocolEvent<K>) -> Vec<Anomaly<K>> {
        self.scratch.clear();
        for rule in &mut self.rules {
            rule.observe(evt, &mut self.scratch);
        }
        std::mem::take(&mut self.scratch)
    }

    /// Drive the time-bound part of every rule. Call once per sweep
    /// tick (the same cadence as your `tokio::time::interval`).
    pub fn on_tick(&mut self, now: Timestamp) -> Vec<Anomaly<K>> {
        self.scratch.clear();
        for rule in &mut self.rules {
            rule.on_tick(now, &mut self.scratch);
        }
        std::mem::take(&mut self.scratch)
    }
}

impl<K> std::fmt::Debug for AnomalyMonitor<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnomalyMonitor")
            .field("rules", &self.rules.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use flowscope::{FlowEvent, FlowSide, Timestamp};

    use super::*;
    use crate::anomaly::rule::Severity;

    type Key = u32;

    fn fake_started(k: Key, ts: u32) -> ProtocolEvent<Key> {
        ProtocolEvent::Flow(FlowEvent::Started {
            key: k,
            side: FlowSide::Initiator,
            l4: None,
            ts: Timestamp::new(ts, 0),
        })
    }

    struct CountEvents {
        count: u64,
        threshold: u64,
    }
    impl AnomalyRule<Key> for CountEvents {
        fn name(&self) -> &'static str {
            "CountEvents"
        }
        fn observe(&mut self, evt: &ProtocolEvent<Key>, emit: &mut Vec<Anomaly<Key>>) {
            self.count += 1;
            if self.count >= self.threshold {
                emit.push(
                    Anomaly::new(self.name(), Severity::Info, evt.timestamp())
                        .with_metric("count", self.count as f64),
                );
            }
        }
    }

    struct OnTickEmit;
    impl AnomalyRule<Key> for OnTickEmit {
        fn name(&self) -> &'static str {
            "OnTickEmit"
        }
        fn observe(&mut self, _: &ProtocolEvent<Key>, _: &mut Vec<Anomaly<Key>>) {}
        fn on_tick(&mut self, now: Timestamp, emit: &mut Vec<Anomaly<Key>>) {
            emit.push(Anomaly::new(self.name(), Severity::Warning, now));
        }
    }

    #[test]
    fn observe_runs_each_rule_in_order() {
        let mut m: AnomalyMonitor<Key> = AnomalyMonitor::new()
            .with_rule(CountEvents {
                count: 0,
                threshold: 1,
            })
            .with_rule(CountEvents {
                count: 0,
                threshold: 2,
            });
        let r1 = m.observe(&fake_started(1, 10));
        // First rule fires (threshold 1), second doesn't (count=1<2).
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].kind, "CountEvents");

        let r2 = m.observe(&fake_started(1, 11));
        // Both fire this time.
        assert_eq!(r2.len(), 2);
    }

    #[test]
    fn observe_returns_empty_when_no_rule_fires() {
        let mut m: AnomalyMonitor<Key> = AnomalyMonitor::new().with_rule(CountEvents {
            count: 0,
            threshold: 999,
        });
        assert!(m.observe(&fake_started(1, 0)).is_empty());
    }

    #[test]
    fn on_tick_is_independent_of_observe() {
        let mut m: AnomalyMonitor<Key> = AnomalyMonitor::new().with_rule(OnTickEmit);
        assert!(m.observe(&fake_started(1, 0)).is_empty());
        let out = m.on_tick(Timestamp::new(42, 0));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ts, Timestamp::new(42, 0));
        assert_eq!(out[0].severity, Severity::Warning);
    }

    #[test]
    fn rule_count_and_names() {
        let m: AnomalyMonitor<Key> =
            AnomalyMonitor::new()
                .with_rule(OnTickEmit)
                .with_rule(CountEvents {
                    count: 0,
                    threshold: 1,
                });
        assert_eq!(m.rule_count(), 2);
        let names: Vec<_> = m.rule_names().collect();
        assert_eq!(names, vec!["OnTickEmit", "CountEvents"]);
    }

    #[test]
    fn empty_monitor_emits_nothing() {
        let mut m: AnomalyMonitor<Key> = AnomalyMonitor::new();
        assert!(m.observe(&fake_started(1, 0)).is_empty());
        assert!(m.on_tick(Timestamp::default()).is_empty());
    }

    #[test]
    fn anomaly_builder_setters() {
        let a: Anomaly<Key> = Anomaly::new("x", Severity::Error, Timestamp::new(5, 0))
            .with_key(7)
            .with_observation("qname", "example.com")
            .with_metric("rtt_ms", 12.5);
        assert_eq!(a.key, Some(7));
        assert_eq!(
            a.context.observations,
            vec![("qname", "example.com".into())]
        );
        assert_eq!(a.context.metrics, vec![("rtt_ms", 12.5)]);
    }

    #[test]
    fn anomaly_display_renders_one_line() {
        let a: Anomaly<Key> = Anomaly::new("DnsBurst", Severity::Warning, Timestamp::new(5, 0))
            .with_key(7)
            .with_observation("src_ip", "10.0.0.1")
            .with_metric("count", 123.4);
        let rendered = format!("{a}");
        assert!(rendered.contains("[warning]"));
        assert!(rendered.contains("DnsBurst"));
        assert!(rendered.contains("ts="));
        assert!(rendered.contains("key=7"));
        assert!(rendered.contains("src_ip=10.0.0.1"));
        assert!(rendered.contains("count=123.40"));
        assert!(!rendered.contains('\n'));
    }

    #[test]
    fn anomaly_display_no_key_no_context_minimal() {
        let a: Anomaly<Key> = Anomaly::new("Tracker", Severity::Info, Timestamp::new(1, 0));
        let rendered = format!("{a}");
        assert!(rendered.contains("[info]"));
        assert!(rendered.contains("Tracker"));
        assert!(!rendered.contains("key="));
    }

    #[test]
    fn anomaly_to_json_line_shape() {
        let a: Anomaly<Key> = Anomaly::new("DnsBurst", Severity::Warning, Timestamp::new(42, 7))
            .with_key(99)
            .with_observation("src_ip", "10.0.0.1")
            .with_metric("count", 123.0)
            .with_metric("rate", 4.5);
        let json = a.to_json_line();
        // Single line — no embedded newline.
        assert!(!json.contains('\n'));
        // Starts and ends with braces.
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        // Field names are quoted; the value-side is whatever they should be.
        assert!(json.contains("\"severity\":\"warning\""));
        assert!(json.contains("\"kind\":\"DnsBurst\""));
        assert!(json.contains("\"ts_secs\":42"));
        assert!(json.contains("\"ts_nanos\":7"));
        assert!(json.contains("\"key\":\"99\""));
        assert!(json.contains("\"observations\":{\"src_ip\":\"10.0.0.1\"}"));
        assert!(json.contains("\"metrics\":{\"count\":123"));
        assert!(json.contains("\"rate\":4.5"));
    }

    #[test]
    fn anomaly_to_json_line_omits_key_when_absent() {
        let a: Anomaly<Key> = Anomaly::new("Tracker", Severity::Info, Timestamp::new(1, 0));
        let json = a.to_json_line();
        assert!(!json.contains("\"key\":"));
        // Observations + metrics still present as empty objects.
        assert!(json.contains("\"observations\":{}"));
        assert!(json.contains("\"metrics\":{}"));
    }

    #[test]
    fn anomaly_to_json_line_escapes_strings() {
        let a: Anomaly<Key> = Anomaly::new("X", Severity::Error, Timestamp::new(0, 0))
            .with_observation("path", "/api/v1\n\"weird\\path\"")
            .with_observation("tab", "a\tb");
        let json = a.to_json_line();
        // No raw newline or unescaped quote inside the value.
        assert!(!json.contains("\n\""));
        assert!(json.contains("\\n"));
        assert!(json.contains("\\\""));
        assert!(json.contains("\\\\"));
        assert!(json.contains("\\t"));
    }

    #[test]
    fn anomaly_emit_tracing_does_not_panic() {
        // Verifies the macro expansion + the per-severity match arms
        // are all wired correctly. Without an installed subscriber
        // the events are dropped, but the call site still must not
        // panic. Each severity goes through its own match arm.
        let make = |sev| {
            Anomaly::<Key>::new("X", sev, Timestamp::new(0, 0))
                .with_key(1)
                .with_observation("o", "v")
                .with_metric("m", 1.5)
        };
        make(Severity::Info).emit_tracing();
        make(Severity::Warning).emit_tracing();
        make(Severity::Error).emit_tracing();
        make(Severity::Critical).emit_tracing();
        // No-key path:
        let nokey: Anomaly<Key> = Anomaly::new("Y", Severity::Warning, Timestamp::new(0, 0));
        nokey.emit_tracing();
    }

    #[test]
    fn anomaly_to_json_line_nan_metric_becomes_null() {
        let a: Anomaly<Key> = Anomaly::new("X", Severity::Info, Timestamp::new(0, 0))
            .with_metric("nan", f64::NAN)
            .with_metric("inf", f64::INFINITY);
        let json = a.to_json_line();
        assert!(json.contains("\"nan\":null"));
        assert!(json.contains("\"inf\":null"));
    }
}
