//! Real-life network diagnostic monitor — three operational signals in
//! one Monitor, expressed with the 0.22 high-level API:
//!
//! 1. **ICMP errors** — Destination Unreachable / Time Exceeded /
//!    Parameter Problem / PMTU, pre-classified (v4 + v6 unified) and
//!    joined back to the originating flow. One `.on_icmp_error(...)`.
//! 2. **TCP connection RESETs** — `.on_tcp_reset(...)`, with a
//!    zero-payload flag to tell "connection refused" from a
//!    mid-transfer abort.
//! 3. **Bandwidth by application** — `.on_bandwidth(...)` hands a typed
//!    [`BandwidthReport`] (top-N apps by bytes/sec) every 5s.
//!
//! This is the 0.22 headline: the 0.21 version of this example was 306
//! lines of hand-rolled ICMP classifiers, a bandwidth HashMap, and a
//! multi-slot tick reporter. The primitives now ship in netring.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_net_diagnostic \
//!     --features "monitor-quickstart,icmp" -- eth0 300
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<seconds>` (default 300).
//! Smoke test on `lo`: `nc -uvz 127.0.0.1 9` lands an ICMPv4 Port
//! Unreachable; `curl http://localhost` (nothing listening) lands a
//! TCP RST.

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    eprintln!("monitor_net_diagnostic: capturing on {iface} for {dur_secs}s");
    eprintln!("                       press Ctrl-C to stop early");

    Monitor::builder()
        .interface(&iface)
        .name("net-diagnostic")
        // ── ICMP errors (v4 + v6, unified + flow-joined) ────────────
        .on_icmp_error(|err: &IcmpError, ctx: &mut Ctx<'_>| {
            // Port Unreachable is routine (a closed UDP port); the rest
            // is worth a warning.
            let severity = match err.kind {
                IcmpErrorKind::DestUnreachable(DestUnreachableKind::Port) => Severity::Info,
                _ => Severity::Warning,
            };
            let mut w = ctx
                .emit("IcmpError", severity)
                .with("kind", err.kind.as_str())
                .with("family", format!("{:?}", err.family));
            if let Some(flow) = err.correlated_flow {
                w = w.with("flow", format!("{flow:?}"));
            }
            if let Some(stats) = &err.stats {
                w = w.with_metric("flow_bytes", stats.total_bytes() as f64);
            }
            w.emit();
            Ok(())
        })
        // ── TCP RESET alerts ────────────────────────────────────────
        .on_tcp_reset(|rst: &TcpRst, ctx: &mut Ctx<'_>| {
            ctx.emit(
                "TcpReset",
                if rst.zero_payload {
                    Severity::Info
                } else {
                    Severity::Warning
                },
            )
            .with("src", format!("{}", rst.key.a))
            .with("dst", format!("{}", rst.key.b))
            .with_metric("bytes", rst.stats.total_bytes() as f64)
            .emit();
            Ok(())
        })
        // ── Bandwidth by application (5s report) ────────────────────
        .on_bandwidth(Duration::from_secs(5), |bw: &BandwidthReport<'_>| {
            println!("─── net_diagnostic: bandwidth ───");
            println!("{:<14} {:>14}", "app", "bytes/sec");
            for (app, bps) in bw.top(10) {
                println!("{app:<14} {bps:>14.0}");
            }
            println!(
                "total: {:.0} B/s across {} apps\n",
                bw.total(),
                bw.app_count()
            );
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_net_diagnostic: done");
    Ok(())
}
