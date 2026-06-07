//! Built-in [`AnomalyRule`] implementations shipped with netring.

use super::rule::{Anomaly, AnomalyRule, Severity};
use crate::protocol::ProtocolEvent;

/// Lifts every [`ProtocolEvent::FlowAnomaly`] /
/// [`ProtocolEvent::TrackerAnomaly`] from the underlying flow
/// tracker into the
/// [`AnomalyMonitor`](super::AnomalyMonitor) pipeline as an
/// [`Anomaly`](super::Anomaly) with
/// the tier coming from
/// [`flowscope::event::AnomalyKind::severity`].
///
/// Use when you want flow-tracker anomalies (TCP out-of-order,
/// reassembler watermark, eviction pressure, parser poison, …) to
/// flow through the same `Vec<Anomaly<K>>` sink as your custom
/// detectors instead of being handled separately.
///
/// `name()` is the static slug `"FlowAnomaly"`. The per-event
/// `kind` (e.g. `"OutOfOrderSegment"`, `"BufferOverflow"`) is
/// surfaced via [`flowscope::event::AnomalyKind`]'s `Display` impl
/// and added to the [`AnomalyContext`](super::AnomalyContext)
/// observations under the `"kind"` label.
///
/// # Example
///
/// ```no_run
/// # #[cfg(all(feature = "tokio", feature = "flow"))]
/// # fn _ex() {
/// use netring::anomaly::{AnomalyMonitor, FlowAnomalyRule};
/// use netring::flow::extract::FiveTupleKey;
///
/// let _monitor = AnomalyMonitor::<FiveTupleKey>::new()
///     .with_rule(FlowAnomalyRule::default());
/// # }
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct FlowAnomalyRule {
    /// Filter floor: anomalies below this tier are ignored. Default
    /// `Severity::Info` (no filtering).
    pub min_severity: Severity,
}

impl FlowAnomalyRule {
    /// Construct with a custom severity floor.
    pub fn with_min_severity(min_severity: Severity) -> Self {
        Self { min_severity }
    }
}

impl<K: Clone> AnomalyRule<K> for FlowAnomalyRule {
    fn name(&self) -> &'static str {
        "FlowAnomaly"
    }

    fn observe(&mut self, evt: &ProtocolEvent<K>, emit: &mut Vec<Anomaly<K>>) {
        const KIND: &str = "FlowAnomaly";
        match evt {
            ProtocolEvent::FlowAnomaly { key, kind, ts } => {
                let sev = Severity::from(kind.severity());
                if sev < self.min_severity {
                    return;
                }
                emit.push(
                    Anomaly::new(KIND, sev, *ts)
                        .with_key(key.clone())
                        .with_observation("kind", kind.short_kind()),
                );
            }
            ProtocolEvent::TrackerAnomaly { kind, ts } => {
                let sev = Severity::from(kind.severity());
                if sev < self.min_severity {
                    return;
                }
                emit.push(Anomaly::new(KIND, sev, *ts).with_observation("kind", kind.short_kind()));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use flowscope::event::AnomalyKind;
    use flowscope::{FlowSide, Timestamp};

    use super::*;
    use crate::anomaly::AnomalyMonitor;

    type Key = u32;

    fn flow_anomaly(k: Key, kind: AnomalyKind, ts: u32) -> ProtocolEvent<Key> {
        ProtocolEvent::FlowAnomaly {
            key: k,
            kind,
            ts: Timestamp::new(ts, 0),
        }
    }

    fn tracker_anomaly(kind: AnomalyKind, ts: u32) -> ProtocolEvent<Key> {
        ProtocolEvent::TrackerAnomaly {
            kind,
            ts: Timestamp::new(ts, 0),
        }
    }

    fn unrelated_flow(k: Key, ts: u32) -> ProtocolEvent<Key> {
        ProtocolEvent::FlowStarted {
            key: k,
            l4: None,
            ts: Timestamp::new(ts, 0),
        }
    }

    #[test]
    fn flow_anomaly_lifts_with_severity_from_flowscope() {
        let mut m: AnomalyMonitor<Key> =
            AnomalyMonitor::new().with_rule(FlowAnomalyRule::default());
        // Out-of-order is Info.
        let out = m.observe(&flow_anomaly(
            7,
            AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 1,
            },
            10,
        ));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Info);
        assert_eq!(out[0].key, Some(7));
        assert_eq!(out[0].kind, "FlowAnomaly");
        assert!(
            out[0]
                .context
                .observations
                .iter()
                .any(|(k, _)| *k == "kind")
        );
    }

    #[test]
    fn tracker_anomaly_lifts_without_key() {
        let mut m: AnomalyMonitor<Key> =
            AnomalyMonitor::new().with_rule(FlowAnomalyRule::default());
        let out = m.observe(&tracker_anomaly(
            AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 1,
            },
            10,
        ));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key, None);
        assert_eq!(out[0].severity, Severity::Warning);
    }

    #[test]
    fn min_severity_filters_below_floor() {
        let mut m: AnomalyMonitor<Key> =
            AnomalyMonitor::new().with_rule(FlowAnomalyRule::with_min_severity(Severity::Warning));
        // Info-level OOO must be filtered.
        let out = m.observe(&flow_anomaly(
            7,
            AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 1,
            },
            10,
        ));
        assert!(out.is_empty());
        // Warning-level eviction pressure passes.
        let out = m.observe(&tracker_anomaly(
            AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 1,
            },
            11,
        ));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn non_anomaly_events_ignored() {
        let mut m: AnomalyMonitor<Key> =
            AnomalyMonitor::new().with_rule(FlowAnomalyRule::default());
        assert!(m.observe(&unrelated_flow(1, 0)).is_empty());
    }
}
