//! 0.21 I.3: beacon/C2 detection via flowscope's `BeaconDetector`
//! + netring's `pattern_detector!` macro.
//!
//! Tracks per-flow inter-arrival times across a sliding window
//! and emits a `BeaconScore` when the variance is low enough to
//! look like a periodic check-in (C2-style traffic).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_beacon_detector \
//!     --features "tokio,flow" -- eth0
//! ```

use std::time::Duration;

use flowscope::detect::patterns::{BeaconDetector, BeaconScore};
use flowscope::extract::FiveTupleKey;
use netring::prelude::*;
use netring::protocol::event_typed::FlowPacket;

/// Wraps the detector + the most recent score so the macro's
/// `verdict:` body can pick up what `feed:` produced.
struct Beacon {
    detector: BeaconDetector<FiveTupleKey>,
    last_score: Option<BeaconScore<FiveTupleKey>>,
}

impl Beacon {
    fn new() -> Self {
        Self {
            detector: BeaconDetector::new(),
            last_score: None,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let beacon = netring::pattern_detector! {
        name: "BeaconCv",
        event: FlowPacket<Tcp>,
        detector: Beacon::new(),
        feed: |evt, w| {
            // Feed `(key, ts, bytes)` into the per-key
            // inter-arrival window. The detector returns
            // `Some(BeaconScore)` once the window has enough
            // samples to score.
            w.last_score = w.detector.observe(evt.key, evt.ts, evt.len as u64);
        },
        verdict: |_evt, w| {
            // Emit only above a confidence threshold; lower
            // scores are noisy. The detector's default tuning
            // produces high scores for well-spaced beacons.
            w.last_score.as_ref().and_then(|s| {
                if s.score >= 0.8 { Some(s.clone()) } else { None }
            })
        },
    };

    Monitor::builder()
        .interface(&iface)
        .name("beacon-c2")
        .protocol::<Tcp>()
        .detect(beacon)
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
