//! Issue #45: YARA payload scanning over reassembled flows.
//!
//! Compiles a couple of YARA rules and scans each flow's accumulated payload at
//! flow end, printing a line per match. Scanning at flow end (over the
//! per-direction payload buffer) lets a signature span TCP segment boundaries —
//! the whole point of scanning the flow rather than each packet.
//!
//! ⚠️ The `yara` feature pulls the cranelift/wasmtime JIT (~150 transitive
//! crates). It's opt-in and never in an umbrella; enable it only when you need
//! content scanning.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_yara --features "yara,tokio" -- eth0
//! ```

use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::yara::{YaraMatch, YaraRules};
use netring::protocol::FlowKey;
use netring::protocol::builtin::Tcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    // In production, load rules from a file / feed. The EICAR string is the
    // standard, harmless antivirus test pattern.
    let rules = YaraRules::compile(
        r#"
        rule eicar {
            strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            condition: $a
        }
        rule shell_payload {
            strings: $a = "/bin/sh" $b = "cmd.exe" nocase
            condition: any of them
        }
        "#,
    )?;

    eprintln!("monitor_yara: scanning TCP flow payloads on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("yara")
        .protocol::<Tcp>()
        .yara(rules)
        // Bound the scan window per direction (default 1 MiB).
        .max_scan_bytes(256 * 1024)
        .on_yara_match(|key: &FlowKey, m: &YaraMatch| {
            println!(
                "YARA hit: rule={} ns={} dir={:?} flow={}<->{}",
                m.rule, m.namespace, m.direction, key.a, key.b
            );
        })
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
