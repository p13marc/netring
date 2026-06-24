//! Issue #47: robust beacon / C2 detection via flowscope's
//! `RitaBeaconDetector` + netring's `pattern_detector!` macro.
//!
//! Like the `monitor_beacon_detector` example, but uses the RITA v5
//! quartile/median statistics (Bowley skewness + median absolute deviation)
//! instead of the coefficient of variation. The median-based scoring survives
//! outliers — a single missed beacon or a retransmit storm barely moves the
//! score, where a mean/stddev CV craters — so it flags **jittered** C2 (e.g.
//! Cobalt Strike's default jitter) that the CV detector misses.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_rita_beacon --features "tokio,flow" -- eth0
//! ```

use std::time::Duration;

use flowscope::detect::patterns::{RitaBeaconDetector, RitaBeaconScore};
use flowscope::extract::FiveTupleKey;
use netring::prelude::*;
use netring::protocol::event_typed::FlowPacket;

/// Wraps the detector + the most recent score so the macro's `verdict:` body
/// can pick up what `feed:` produced.
struct RitaBeacon {
    detector: RitaBeaconDetector<FiveTupleKey>,
    last_score: Option<RitaBeaconScore<FiveTupleKey>>,
}

impl RitaBeacon {
    fn new() -> Self {
        Self {
            detector: RitaBeaconDetector::new(),
            last_score: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let beacon = netring::pattern_detector! {
        name: "BeaconRita",
        event: FlowPacket,
        detector: RitaBeacon::new(),
        feed: |evt, w| {
            // Feed `(key, ts, bytes)` per flow packet; the detector scores
            // once the per-key window has ≥ 10 samples. Scope to TCP via
            // `evt.proto` (FlowPacket is flat across L4).
            if matches!(evt.proto, L4Proto::Tcp) {
                w.last_score = w.detector.observe(evt.key, evt.ts, evt.len as u64);
            }
        },
        verdict: |_evt, w| {
            // RITA's robust score runs high for regular AND jittered beacons;
            // 0.9 is a conservative C2 threshold.
            w.last_score.as_ref().and_then(|s| {
                if s.score >= 0.9 { Some(s.clone()) } else { None }
            })
        },
    };

    eprintln!("monitor_rita_beacon: robust beacon scoring on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("rita-beacon")
        .protocol::<Tcp>()
        .detect(beacon)
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
