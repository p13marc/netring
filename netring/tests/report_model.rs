//! 0.22 §3 — the report model: `report()` closure snapshots + a typed
//! `Report` shipped through a `ReportSink` via `report_to()`.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netring::monitor::{BandwidthSnapshot, Monitor};
use netring::prelude::*;
use netring::report::{Report, ReportSink};

#[test]
fn report_and_report_to_build() {
    // Closure form: snapshot accessors compile + are wired.
    let _m: Monitor = Monitor::builder()
        .interface("lo")
        .bandwidth_by_app()
        .report(Duration::from_secs(5), |snap: ReportSnapshot<'_, '_>| {
            if let Some(bw) = snap.bandwidth() {
                let _ = bw.total();
            }
            let _ = snap.now();
            Ok(())
        })
        .build()
        .expect("report builds");

    // Typed form: BandwidthSnapshot (a Report) → a custom ReportSink.
    let _m2: Monitor = Monitor::builder()
        .interface("lo")
        .bandwidth_by_app()
        .report_to(
            Duration::from_secs(5),
            |snap: ReportSnapshot<'_, '_>| {
                snap.bandwidth()
                    .map(|bw| bw.to_snapshot(10))
                    .unwrap_or(BandwidthSnapshot { apps: vec![] })
            },
            StdoutReportSink,
        )
        .build()
        .expect("report_to builds");
}

#[derive(Debug)]
struct Heartbeat {
    n: u64,
}
impl Report for Heartbeat {
    const NAME: &'static str = "heartbeat";
}

/// A capturing ReportSink to assert reports flow through (without a
/// live capture, by driving the registered tick handler directly is
/// out of scope here — this pins the trait wiring + Report::NAME).
struct CapturingSink(Arc<Mutex<Vec<u64>>>);
impl ReportSink<Heartbeat> for CapturingSink {
    fn record(&mut self, report: &Heartbeat) {
        self.0.lock().unwrap().push(report.n);
    }
}

#[test]
fn custom_report_sink_records() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut sink = CapturingSink(Arc::clone(&seen));
    sink.record(&Heartbeat { n: 7 });
    sink.record(&Heartbeat { n: 9 });
    assert_eq!(*seen.lock().unwrap(), vec![7, 9]);
    assert_eq!(Heartbeat::NAME, "heartbeat");
}
