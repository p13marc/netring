//! Issue #31: passive TCP/OS fingerprinting (p0f).
//!
//! Every TCP SYN / SYN-ACK leaks the sender's OS through its stack defaults —
//! initial TTL, window size, MSS, option layout, quirks. This prints a p0f-3
//! signature per handshake, identifying client and server operating systems
//! without touching the payload. No active probing.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_p0f --features "tokio,p0f,emit" -- eth0
//! ```

use std::time::Duration;

use flowscope::{TcpDirection, TcpFingerprint};
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("p0f")
        .on_p0f(|fp: &TcpFingerprint, ctx: &mut Ctx<'_>| {
            let role = match fp.direction {
                TcpDirection::Syn => "client",
                TcpDirection::SynAck => "server",
                _ => "?",
            };
            ctx.emit("P0fFingerprint", Severity::Info)
                .with("role", role)
                .with("signature", fp.to_p0f_signature())
                .with_metric("observed_ttl", fp.observed_ttl as f64)
                .emit();
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
