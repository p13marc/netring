//! Suricata-compatible EVE `event_type:"tls"` records (0.25 W1d).
//!
//! Logs every observed TLS handshake as an EVE `tls` record (sni, ja3.hash,
//! ja4, alpn, 5-tuple) via [`EveTlsSink`] — the protocol-record companion to
//! [`EveSink`](netring::anomaly::EveSink)'s `event_type:"anomaly"`. Drop the
//! NDJSON into a Suricata-aware pipeline (Filebeat / Tenzir / Elastic).
//!
//! ```sh
//! cargo run --example monitor_eve_tls --features "monitor,eve-sink" -- eth0
//! # each TLS handshake → one JSON line: {"event_type":"tls","tls":{"sni":..}}
//! ```

use std::sync::{Arc, Mutex};

use netring::anomaly::EveTlsSink;
use netring::monitor::Monitor;

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

    // The sink owns stdout; share it into the fingerprint handler.
    let sink = Arc::new(Mutex::new(EveTlsSink::new(std::io::stdout(), &iface)));
    let handler_sink = Arc::clone(&sink);

    let monitor = Monitor::builder()
        .interface(&iface)
        // `on_fingerprint` registers the TLS-handshake parser + hands each
        // fingerprint (with the flow key) to the closure.
        .on_fingerprint(move |fp, ctx| {
            let _ = handler_sink.lock().unwrap().write_tls(fp, ctx.ts);
            Ok(())
        })
        .build()?;

    eprintln!("# logging TLS handshakes as EVE `tls` records on {iface} (Ctrl-C to stop)");
    monitor.run_until_signal().await
}
