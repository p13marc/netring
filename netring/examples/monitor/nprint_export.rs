//! Issue #72: per-flow nPrint matrix export.
//!
//! nPrint (CCS 2021) is a standardized, model-agnostic representation of a
//! packet as a ternary header-bit vector (`-1` absent, `0`, `1`). Stacking one
//! row per packet gives a per-flow matrix you can feed straight into an ML
//! pipeline without hand-engineering features.
//!
//! This arms the Monitor with `.nprint(..)` so every packet of every tracked
//! flow is decoded into a row; at flow end `.on_nprint(..)` receives the
//! completed [`NPrintMatrix`], which we dump as one CSV line per packet
//! (`flow,packet_index,bit0,bit1,...`). Redirect stdout to a `.csv` and label
//! offline for training.
//!
//! Per-packet retention is heavy (~43 KiB per flow at the 100-packet default),
//! so the live-flow set is bounded — see `max_tracked_nprint_flows`.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_nprint --features "tokio,nprint" -- eth0 > flows.csv
//! ```

use std::time::Duration;

use flowscope::nprint::{NPrintConfig, NPrintMatrix};
use netring::monitor::Monitor;
use netring::protocol::FlowKey;
use netring::protocol::builtin::Tcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    eprintln!("monitor_nprint: writing per-flow nPrint rows for TCP on {iface} (Ctrl-C to stop)");
    eprintln!("# columns: flow,packet_index,<bit_0..bit_N as -1/0/1>");

    Monitor::builder()
        .interface(&iface)
        .name("nprint")
        .protocol::<Tcp>()
        // eth + ipv4 + tcp + udp, 100 packets/flow (the default shape).
        .nprint(NPrintConfig::default())
        .max_tracked_nprint_flows(4096)
        .on_nprint(|key: &FlowKey, matrix: &NPrintMatrix| {
            let flow = format!("{}-{}", key.a, key.b);
            for (i, row) in matrix.rows().iter().enumerate() {
                // One CSV line per packet: bits as -1/0/1.
                let mut line = String::with_capacity(row.bits.len() * 3 + 32);
                line.push_str(&flow);
                line.push(',');
                line.push_str(&i.to_string());
                for bit in &row.bits {
                    line.push(',');
                    line.push_str(itoa_i8(bit.as_raw()));
                }
                println!("{line}");
            }
        })
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}

/// Tiny `-1`/`0`/`1` formatter (the only three values `NPrintBit::as_raw`
/// returns) — avoids a per-bit heap allocation in the hot dump loop.
fn itoa_i8(v: i8) -> &'static str {
    match v {
        1 => "1",
        0 => "0",
        _ => "-1",
    }
}
