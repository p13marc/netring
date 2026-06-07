//! Write a Zeek-compatible `conn.log` from a live flow stream,
//! using flowscope's [`ZeekConnLogWriter`](flowscope::emit::ZeekConnLogWriter).
//!
//! Useful pivot when an existing Zeek-based SIEM / log pipeline
//! needs to ingest flow data without a Zeek deployment.
//!
//! Usage:
//!     cargo run -p netring --example zeek_export \
//!         --features tokio,flow,parse -- [interface] [seconds] [output.log]
//!
//! Defaults: lo, 60s, ./conn.log
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::BufWriter;
    use std::time::{Duration, Instant};

    use flowscope::FlowEvent;
    use flowscope::emit::ZeekConnLogWriter;
    use futures::StreamExt;
    use netring::AsyncCapture;
    use netring::flow::extract::FiveTuple;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let out_path = std::env::args().nth(3).unwrap_or_else(|| "conn.log".into());

    eprintln!("[zeek] watching {iface} for {seconds}s; writing → {out_path}");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    let sink = BufWriter::new(File::create(&out_path)?);
    let mut writer = ZeekConnLogWriter::new(sink)?;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut written = 0u64;

    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        let event = evt?;
        // Zeek's conn.log records one row per terminated flow.
        if matches!(event, FlowEvent::Ended { .. }) {
            writer.write_event(&event)?;
            written += 1;
        }
    }

    writer.flush()?;
    eprintln!("[done] wrote {written} flow records to {out_path}");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow", feature = "parse")))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse");
}
