//! Encrypted-DNS visibility (issue #133): flag DoH / DoT / DoQ sessions and the
//! resolver they target.
//!
//! Once DNS moves inside TLS or QUIC the query names are gone, but the *fact* of
//! encrypted DNS — and to which resolver — is a policy-relevant signal.
//! `.on_encrypted_dns(|e, ctx| …)` fires with the classified protocol, the
//! resolver SNI, and whether it's a well-known public resolver.
//!
//! ```sh
//! cargo run --example monitor_encrypted_dns --features "tokio,tls,quic" -- eth0
//! ```

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_encrypted_dns: DoH/DoT/DoQ watch on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .on_encrypted_dns(|e, _ctx| {
            let resolver = e.sni.as_deref().unwrap_or("<no SNI>");
            let known = if e.via_known_resolver {
                " (known public resolver)"
            } else {
                ""
            };
            println!("{:?} → {resolver}{known}", e.app_protocol);
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
