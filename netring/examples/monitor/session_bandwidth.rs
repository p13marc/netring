//! Bandwidth per **session** (5-tuple: src ip:port → dst ip:port).
//!
//! Two complementary views:
//!
//! 1. **Rolling top-N active sessions** by bytes/sec — a `BandwidthByKey<FlowKey>`
//!    fed on every `FlowPacket`, reported on a timer. This is the "which
//!    connections are hot right now" view (the per-flow analogue of the traffic
//!    matrix in `monitor_traffic_aggregation`).
//! 2. **Cumulative at flow end** — `FlowEnded.stats` already carries
//!    `bytes_initiator` / `bytes_responder` and the flow duration, so total bytes
//!    and average throughput per connection come for free, no extra state.
//!
//! ```sh
//! cargo run --example monitor_session_bandwidth --features "tokio,flow" -- eth0
//! ```

use std::time::Duration;

use flowscope::correlate::BandwidthByKey;
use netring::prelude::*;
use netring::protocol::FlowKey;
use netring::protocol::event_typed::{FlowPacket, Tick};

/// Rolling per-5-tuple byte-rate table (60 s window, 5 s buckets).
struct SessionRates(BandwidthByKey<FlowKey>);

impl Default for SessionRates {
    fn default() -> Self {
        Self(BandwidthByKey::new_unbounded(
            Duration::from_secs(60),
            Duration::from_secs(5),
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_session_bandwidth: per-5-tuple bandwidth on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .protocol::<Udp>()
        // (1) Feed every packet's length into the per-flow rate table.
        .on_ctx::<FlowPacket>(|evt: &FlowPacket, ctx: &mut Ctx<'_>| {
            let ts = ctx.ts;
            ctx.state_mut::<SessionRates>()
                .0
                .record_tx(evt.key, evt.len as u64, ts);
            Ok(())
        })
        // Rolling top-N active sessions, every 10s.
        .tick(Duration::from_secs(10), |tick: &Tick, ctx: &mut Ctx<'_>| {
            if let Some(s) = ctx.state::<SessionRates>() {
                println!("── top active sessions (bytes/sec) ──────────");
                for (k, bps) in s.0.top_k(10, tick.now) {
                    println!(
                        "  {}:{} → {}:{}  {bps:>12.0} B/s",
                        k.a.ip(),
                        k.a.port(),
                        k.b.ip(),
                        k.b.port(),
                    );
                }
            }
            Ok(())
        })
        // (2) Cumulative total + average throughput at flow end.
        .on_ctx::<FlowEnded<Tcp>>(|e: &FlowEnded<Tcp>, _ctx: &mut Ctx<'_>| {
            report_flow_end(
                "tcp",
                e.key,
                e.stats.bytes_initiator + e.stats.bytes_responder,
                e.stats.duration_secs(),
            );
            Ok(())
        })
        .on_ctx::<FlowEnded<Udp>>(|e: &FlowEnded<Udp>, _ctx: &mut Ctx<'_>| {
            report_flow_end(
                "udp",
                e.key,
                e.stats.bytes_initiator + e.stats.bytes_responder,
                e.stats.duration_secs(),
            );
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}

fn report_flow_end(proto: &str, k: FlowKey, bytes: u64, secs: f64) {
    let rate = if secs > 0.0 { bytes as f64 / secs } else { 0.0 };
    println!(
        "flow end {proto} {}:{} → {}:{}  {bytes} B over {secs:.1}s = {rate:.0} B/s avg",
        k.a.ip(),
        k.a.port(),
        k.b.ip(),
        k.b.port(),
    );
}
