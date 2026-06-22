//! Issue #14: passive QUIC SNI / ALPN visibility (HTTP/3 destinations).
//!
//! As traffic moves off TCP+TLS onto QUIC (UDP/443, HTTP/3), a TLS-SNI tap goes
//! blind. This surfaces the destination hostname and ALPN from the **QUIC
//! Initial** packet — whose protection secret is a published RFC 9001 constant,
//! so the ClientHello inside is passive-readable without any decryption keys.
//!
//! No active probing, no MITM. Prints `dst_ip sni=… alpn=… version=…` per
//! observed QUIC handshake.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_quic_sni --features "tokio,quic,emit" -- eth0
//! ```

use std::time::Duration;

use flowscope::QuicInitial;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("quic-sni")
        .protocol::<Quic>()
        .on_ctx::<Quic>(|m: &QuicInitial, ctx: &mut Ctx<'_>| {
            // Surface the destination hostname an HTTP/3 client is dialing.
            if let Some(sni) = &m.sni {
                ctx.emit("QuicSni", Severity::Info)
                    .with("sni", sni.clone())
                    .with("alpn", m.alpn.join(","))
                    .with("version", format!("{:?}", m.version))
                    .emit();
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
