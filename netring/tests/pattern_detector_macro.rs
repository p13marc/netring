//! 0.21 I.1: `pattern_detector!` macro smoke test.
//!
//! Uses a hand-rolled toy detector (not flowscope's
//! `PortScanDetector`) so the test stays insulated from upstream
//! API changes. The toy detector implements
//! `flowscope::DetectorScore` directly so it routes through
//! `publish_owned` the same way real detectors do.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use flowscope::Timestamp;
use flowscope::event::Severity as FsSeverity;
use flowscope::extract::FiveTupleKey;
use netring::anomaly::DetectorScore;
use netring::anomaly::sink::AnomalySink;
use netring::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

/// Toy "scanner score" — emits an anomaly whenever the count
/// crosses a threshold.
#[derive(Default)]
struct ToyScanner {
    count: u32,
}

struct ToyScore {
    count: u32,
}

impl DetectorScore for ToyScore {
    fn name(&self) -> &'static str {
        "ToyScan"
    }
    fn into_anomaly(self, ts: Timestamp) -> flowscope::OwnedAnomaly {
        flowscope::OwnedAnomaly::new("ToyScan", FsSeverity::Warning, ts)
            .with_metric("count", self.count as f64)
    }
}

/// Capture sink for assertions — records `(kind, severity, metric_count)`.
#[derive(Default)]
struct Capture {
    events: Vec<(&'static str, netring::anomaly::Severity, f64)>,
}

impl AnomalySink for Capture {
    fn write(
        &mut self,
        kind: &'static str,
        severity: netring::anomaly::Severity,
        _ts: Timestamp,
        _key: Option<&dyn netring::anomaly::Key>,
        _observations: &[(&'static str, std::borrow::Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let count = metrics
            .iter()
            .find(|(k, _)| *k == "count")
            .map(|(_, v)| *v)
            .unwrap_or(0.0);
        self.events.push((kind, severity, count));
    }
}

fn dummy_evt() -> FlowStarted<Tcp> {
    let key = FiveTupleKey {
        proto: flowscope::L4Proto::Tcp,
        a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    };
    FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
}

#[test]
fn pattern_detector_macro_threads_through_publish_owned() {
    let fired = Arc::new(AtomicU32::new(0));
    let f = Arc::clone(&fired);

    let det = netring::pattern_detector! {
        name: "ToyScan",
        event: FlowStarted<Tcp>,
        detector: ToyScanner::default(),
        feed: |_evt, det| {
            det.count += 1;
            f.fetch_add(1, Ordering::Relaxed);
        },
        verdict: |_evt, det| {
            if det.count >= 3 {
                Some(ToyScore { count: det.count })
            } else {
                None
            }
        },
    };

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(det);
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = Capture::default();
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();
    let mut ctx = Ctx::new(
        None,
        Timestamp::new(0, 0),
        SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );

    let evt = dummy_evt();
    for _ in 0..5 {
        disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
    }

    // feed body ran 5 times.
    assert_eq!(fired.load(Ordering::Relaxed), 5);
    // verdict body returned Some only when count >= 3 → 3 emissions.
    assert_eq!(sink.events.len(), 3);
    // Each emission has the right kind + severity + grows with count.
    let counts: Vec<f64> = sink.events.iter().map(|(_, _, c)| *c).collect();
    assert_eq!(counts, vec![3.0, 4.0, 5.0]);
    for (kind, sev, _) in &sink.events {
        assert_eq!(*kind, "ToyScan");
        assert_eq!(*sev, netring::anomaly::Severity::Warning);
    }
}

#[test]
fn pattern_detector_name_stamps_on_detector() {
    use netring::monitor::Handler;

    let det = netring::pattern_detector! {
        name: "PatternX",
        event: FlowStarted<Tcp>,
        detector: ToyScanner::default(),
        feed: |_evt, _det| {},
        verdict: |_evt, _det| None::<ToyScore>,
    };
    assert_eq!(det.name, "PatternX");
    // And it still satisfies the Handler trait (compile-time check).
    fn _accept<H>(_: H)
    where
        H: Handler<FlowStarted<Tcp>, netring::monitor::PayloadCtx>,
    {
    }
    _accept(det);
}
