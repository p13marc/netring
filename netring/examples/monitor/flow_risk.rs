//! Issue #49: passive nDPI-style flow-risk scoring.
//!
//! Arms the built-in deterministic risk checks and prints a `flow_risk` finding
//! per hit:
//!   * `obsolete_tls` — a handshake that negotiated SSLv3 / TLS 1.0 / TLS 1.1
//!     (deprecated per RFC 8996).
//!   * `cleartext_http_credentials` — an HTTP request carrying
//!     `Authorization: Basic` (a password base64'd over plaintext HTTP).
//!
//! No active probing; both signals are read from the parsed handshake / request.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_flow_risk --features "tokio,tls,http,emit" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_flow_risk: scoring traffic risk on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("flow-risk")
        .flow_risk()
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
