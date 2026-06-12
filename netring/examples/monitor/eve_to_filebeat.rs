//! 0.21 B.2 — `EveSink` to a file ready for Filebeat ingest.
//!
//! Wires the declarative `Monitor` to flowscope's
//! `EveJsonWriter` via `EveSink`. Output is Suricata-compatible
//! EVE JSON (one record per line) — drop the file into Filebeat's
//! Suricata module, Splunk's Suricata TA, Tenzir's
//! `read_suricata` pipeline, or any ECS-aware converter.
//!
//! Each TCP flow start emits a `FlowStartedTcp` anomaly with
//! observation labels for the 5-tuple. Real deployments would
//! gate Severity through `MinSeverity::warning()` and add
//! `DedupeAnomalies` to keep ingest volume sane.
//!
//! ```sh
//! cargo run --example monitor_eve_to_filebeat \
//!     --features "monitor-quickstart" -- eth0 eve.json 30
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<eve_path>` (default
//! `eve.json`) `<seconds>` (default 30).

use std::fs::OpenOptions;
use std::io::BufWriter;
use std::time::Duration;

use flowscope::emit::EveOptions;
use netring::anomaly::EveSink;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let path = std::env::args().nth(2).unwrap_or_else(|| "eve.json".into());
    let dur_secs: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("monitor_eve_to_filebeat: writing EVE JSON to {path} for {dur_secs}s on {iface}");

    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let eve = EveSink::new(BufWriter::new(file), EveOptions::default());

    Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .on_ctx::<FlowStarted<Tcp>>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            let ts = ctx.ts;
            ctx.sink_mut()
                .begin("FlowStartedTcp", Severity::Info, ts)
                .with("src", format!("{}", evt.key.a))
                .with("dst", format!("{}", evt.key.b))
                .emit();
            Ok(())
        })
        .layer(MinSeverity::at_least(Severity::Info))
        .sink(eve)
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_eve_to_filebeat: done — tail -f {path} | filebeat -e -c filebeat.yml");
    Ok(())
}
