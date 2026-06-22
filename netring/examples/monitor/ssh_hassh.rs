//! Issue #30: passive SSH visibility + HASSH fingerprinting.
//!
//! Surfaces flowscope 0.18's SSH parser through the Monitor and emits the
//! version banner and the HASSH / HASSHServer handshake fingerprints — the
//! SSH analogue of JA3/JA4, useful for asset inventory and spotting anomalous
//! clients (a HASSH that doesn't match your fleet's standard SSH client).
//!
//! Parsing is passive and stops at key exchange — everything after
//! `SSH_MSG_NEWKEYS` is encrypted.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_ssh_hassh --features "tokio,ssh,emit" -- eth0
//! ```

use std::time::Duration;

use flowscope::ssh::SshMessage;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("ssh-hassh")
        .protocol::<Ssh>()
        .on_ctx::<Ssh>(|m: &SshMessage, ctx: &mut Ctx<'_>| {
            match m {
                SshMessage::Banner { banner } => {
                    ctx.emit("SshBanner", Severity::Info)
                        .with("banner", banner.clone())
                        .emit();
                }
                SshMessage::KexInit(k) => {
                    let kind = if k.from_client {
                        "hassh"
                    } else {
                        "hassh_server"
                    };
                    ctx.emit("SshHassh", Severity::Info)
                        .with("kind", kind)
                        .with("hassh", k.hassh.clone())
                        .emit();
                }
                SshMessage::Encrypted => {}
                _ => {}
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
