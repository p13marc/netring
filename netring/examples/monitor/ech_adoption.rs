//! 0.21 I.8: ECH (Encrypted Client Hello) adoption + downgrade
//! detection from TLS handshakes.
//!
//! Subscribes to flowscope's `TlsHandshakeParser`-emitted
//! `TlsHandshake` aggregate (per-flow, one message per completed
//! handshake) and emits one of:
//!
//! - `EchAccepted` (Info) — client offered ECH and the server's
//!   plaintext didn't carry retry_configs → ECH active.
//! - `EchRejected` (Warning) — server's EncryptedExtensions
//!   carried plaintext retry_configs → explicit downgrade signal.
//! - `EchOutcome::NotOffered` / `Unknown` — no emit (default
//!   no-ECH paths or indeterminate handshakes are noise).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_ech_adoption \
//!     --features "tokio,flow,tls" -- eth0
//! ```
//!
//! Pair with `curl --ech grease https://crypto.cloudflare.com/cdn-cgi/trace`
//! over the watched interface to exercise the ECH-Accepted path.

use std::time::Duration;

use flowscope::tls::EchOutcome;
use netring::prelude::*;
use netring::protocol::builtin::TlsHandshake;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("ech-adoption")
        .protocol::<TlsHandshake>()
        .on_ctx::<TlsHandshake>(|hs: &flowscope::tls::TlsHandshake, ctx: &mut Ctx<'_>| {
            let sni = hs.sni.as_deref().unwrap_or("<no-sni>");
            match hs.ech_outcome {
                EchOutcome::Accepted => {
                    ctx.emit("EchAccepted", Severity::Info)
                        .with("sni", sni.to_string())
                        .emit();
                }
                EchOutcome::Rejected => {
                    ctx.emit("EchRejected", Severity::Warning)
                        .with("sni", sni.to_string())
                        .with("note", "server signaled ECH downgrade via retry_configs")
                        .emit();
                }
                EchOutcome::NotOffered | EchOutcome::Unknown => {
                    // No-ECH paths are uninteresting; don't spam.
                }
                _ => {
                    // `EchOutcome` is `#[non_exhaustive]`; future
                    // variants fall through to no-op until the
                    // example is updated.
                }
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(60))
        .await?;

    Ok(())
}
