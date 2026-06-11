//! 0.21 I.2: port-scan detection via flowscope's
//! `PortScanDetector` + netring's `pattern_detector!` macro.
//!
//! Uses TRW (Threshold Random Walk): each completed TCP
//! connection nudges the source's log-likelihood toward "benign";
//! each failed connection (RST / idle) nudges it toward
//! "scanner". When the log-likelihood crosses the upper or lower
//! threshold the detector emits a `ScanScore` and resets state
//! for that source.
//!
//! We listen to `FlowEnded<Tcp>` (not `FlowStarted`) so the
//! `success` bit is well-defined: success = "flow ended cleanly"
//! (FIN/Idle), failure = "flow died" (RST/ParseError/eviction).
//!
//! Anomalies emit only when the detector's verdict is `Scanner`;
//! `Benign` and `Inconclusive` would be log spam.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_port_scan \
//!     --features "tokio,flow" -- eth0
//! ```

use std::time::Duration;

use flowscope::EndReason;
use flowscope::detect::patterns::{PortScanDetector, ScanScore, ScanVerdict};
use flowscope::extract::FiveTupleKey;
use netring::prelude::*;
use netring::protocol::event_typed::FlowEnded;

/// Detector wrapper that stashes the most recent `ScanScore` so
/// the macro's `verdict:` body can read it after `feed:` wrote
/// it. The `pattern_detector!` macro doesn't pass state from
/// `feed` to `verdict` directly; the wrapper bridges the gap.
///
/// Note: this keys on `FiveTupleKey` rather than source IP, so
/// the TRW walk doesn't aggregate across flows from the same
/// scanner. A production version would key the detector on a
/// source-IP newtype that impls `flowscope::KeyFields`; this
/// demo's intent is to show the macro shape, not to replace
/// Suricata's scan detector.
struct PortScan {
    detector: PortScanDetector<FiveTupleKey>,
    last_score: Option<ScanScore<FiveTupleKey>>,
}

impl PortScan {
    fn new() -> Self {
        Self {
            detector: PortScanDetector::new(),
            last_score: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let scan = netring::pattern_detector! {
        name: "PortScanTRW",
        event: FlowEnded<Tcp>,
        detector: PortScan::new(),
        feed: |evt, w| {
            let success = matches!(evt.reason, EndReason::Fin | EndReason::IdleTimeout);
            w.last_score = Some(w.detector.observe(evt.key, success));
        },
        verdict: |_evt, w| {
            // Emit only on Scanner verdicts. Benign + Inconclusive
            // are noise for a live alert pipeline.
            w.last_score.as_ref().and_then(|s| {
                if matches!(s.verdict, ScanVerdict::Scanner) {
                    Some(s.clone())
                } else {
                    None
                }
            })
        },
    };

    Monitor::builder()
        .interface(&iface)
        .name("port-scan-trw")
        .protocol::<Tcp>()
        .detect(scan)
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(60))
        .await?;

    Ok(())
}
