//! 0.21 I.4: DGA (Domain Generation Algorithm) detection via
//! flowscope's `DgaScorer` + netring's `pattern_detector!` macro.
//!
//! Scores every DNS query name's second-level domain against the
//! bundled English-baseline bigram table. Below a log-likelihood
//! threshold = highly DGA-like = emit anomaly.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_dga_query \
//!     --features "tokio,flow,dns" -- eth0
//! ```

use std::time::Duration;

use flowscope::detect::patterns::{DgaScore, DgaScorer};
use flowscope::dns::DnsMessage;
use netring::prelude::*;

/// Wraps the scorer + the most recent score so the macro's
/// `verdict:` body can pick up what `feed:` computed.
struct Dga {
    scorer: DgaScorer,
    last_query: Option<String>,
    last_score: Option<DgaScore>,
}

impl Dga {
    fn new() -> Self {
        Self {
            scorer: DgaScorer::new(),
            last_query: None,
            last_score: None,
        }
    }
}

/// Extract the second-level domain (e.g. "kj3h4kj.com" → "kj3h4kj").
fn extract_sld(qname: &str) -> Option<&str> {
    let trimmed = qname.trim_end_matches('.');
    let mut parts = trimmed.rsplit('.');
    let _tld = parts.next()?;
    parts.next()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let dga = netring::pattern_detector! {
        name: "DgaScorer",
        event: Dns,
        detector: Dga::new(),
        feed: |msg, w| {
            if let DnsMessage::Query(q) = msg
                && let Some(question) = q.questions.first()
                && let Some(sld) = extract_sld(&question.name) {
                    w.last_query = Some(sld.to_string());
                    w.last_score = Some(w.scorer.score(sld));
                }
        },
        verdict: |_msg, w| {
            // log_likelihood threshold: more negative = more
            // DGA-like. -8.0 is a moderately aggressive cut.
            w.last_score.as_ref().and_then(|s| {
                if s.log_likelihood < -8.0 {
                    Some(*s)
                } else {
                    None
                }
            })
        },
    };

    Monitor::builder()
        .interface(&iface)
        .name("dga-watch")
        .protocol::<Dns>()
        .detect(dga)
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
