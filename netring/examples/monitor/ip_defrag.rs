//! IP-fragment reassembly (issue #134): defeat fragmentation-based evasion.
//!
//! `.reassemble_ip_fragments()` (off by default) feeds each IPv4 fragment to a
//! reassembler before the flow tracker parses it, so a payload split across
//! fragments — the classic IDS/NSM evasion — reaches the L7 parsers whole. Only
//! the tracker input is reassembled; per-frame taps still see raw wire
//! fragments. Overlapping fragments (teardrop / RFC 5722) are dropped.
//!
//! This demo replays the fragmented-DNS fixture shape: with reassembly armed the
//! DNS response parses; without it, the fragments are opaque. Point `--` at a
//! pcap containing fragmented traffic, or an interface.
//!
//! ```sh
//! cargo run --example monitor_ip_defrag --features "tokio,flow,dns" -- eth0
//! ```

use netring::monitor::ip_frag::IpFragConfig;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_ip_defrag: reassembling IPv4 fragments on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        // Defaults mirror flowscope's FragmentConfig; tune caps/timeout via
        // reassemble_ip_fragments_with(IpFragConfig { .. }).
        .reassemble_ip_fragments_with(IpFragConfig::default())
        .on_dns(|v, _ctx| {
            if let Some(qname) = v.qname() {
                println!("dns (post-reassembly) {qname}");
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
