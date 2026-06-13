//! Real-life network diagnostic monitor — three signals in one
//! Monitor:
//!
//! 1. **ICMP Destination Unreachable** alerts split per code
//!    (host unreachable, port unreachable, network unreachable,
//!    administratively prohibited, etc.). v4 + v6 both covered.
//! 2. **TCP connection RESET** alerts via `FlowEnded<Tcp>` with
//!    `EndReason::Rst`. Includes byte counts at reset so you can
//!    tell "RST after handshake" from "RST mid-transfer".
//! 3. **Bandwidth by application** — bytes + packets accumulated
//!    per protocol label (`http`, `https`, `dns`, `ssh`, …) from
//!    flowscope's well-known port table. Both TCP and UDP feed
//!    one bucket map. A periodic tick prints a sorted report.
//!
//! Composition shape:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Icmp protocol                                               │
//! │  └─ on::<Icmp>      → classify Destination Unreachable      │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Tcp protocol                                                │
//! │  ├─ on::<FlowEnded<Tcp>>  → RST alerts                      │
//! │  └─ on::<FlowPacket<Tcp>> → bandwidth bucket                │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Udp protocol                                                │
//! │  └─ on::<FlowPacket<Udp>> → bandwidth bucket                │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Tick (5s)             → print bandwidth report + totals     │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! Three independent state slots (one per signal) keep the
//! handler bodies tight — `ctx.state_mut::<T>()` projects whichever
//! one the handler needs.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_net_diagnostic \
//!     --features "monitor-quickstart,icmp" -- eth0 300
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<seconds>` (default 300).
//!
//! Companion: pair with `synthetic_traffic` on lo for a smoke
//! test without real outbound traffic. `nc -uvz 127.0.0.1 9` will
//! land an ICMPv4 Port Unreachable on lo; `curl http://localhost`
//! (against nothing listening) will land a TCP RST.

use std::time::Duration;

use flowscope::EndReason;
use flowscope::icmp::{
    IcmpMessage, IcmpType, Icmpv4DestUnreachCode, Icmpv4Type, Icmpv6DestUnreachCode, Icmpv6Type,
};
use netring::prelude::*;
use netring::protocol::event_typed::FlowPacket;
use rustc_hash::FxHashMap;

#[derive(Default)]
struct AppBandwidth {
    /// `protocol_label()` → bytes + packets accumulated since
    /// monitor start (cumulative; printed deltas would be a
    /// trivial extension — store last-tick snapshot next to
    /// each bucket).
    by_app: FxHashMap<&'static str, AppBucket>,
    /// Catch-all for flows where neither port is in the
    /// well-known table.
    other_tcp: AppBucket,
    other_udp: AppBucket,
}

#[derive(Default, Copy, Clone)]
struct AppBucket {
    bytes: u64,
    packets: u64,
}

impl AppBucket {
    fn add(&mut self, len: usize) {
        self.bytes += len as u64;
        self.packets += 1;
    }
}

#[derive(Default, Copy, Clone)]
struct TcpResetCount {
    total: u64,
    /// Resets that occurred before any payload moved — likely
    /// "connection refused" at the application layer (after the
    /// kernel-level SYN/ACK).
    zero_payload: u64,
}

#[derive(Default, Copy, Clone)]
struct IcmpUnreachableCount {
    host: u64,
    port: u64,
    network: u64,
    prohibited: u64,
    other: u64,
}

/// Classify a parsed ICMP message as a Destination Unreachable
/// alert. Returns `Some((label, severity))` if this is one;
/// `None` for echo / time exceeded / neighbor discovery / etc.
fn classify_unreachable(msg: &IcmpMessage) -> Option<(&'static str, Severity)> {
    match &msg.ty {
        IcmpType::V4(Icmpv4Type::DestinationUnreachable { code, .. }) => match code {
            Icmpv4DestUnreachCode::Host | Icmpv4DestUnreachCode::DestHostUnknown => {
                Some(("host_unreachable", Severity::Warning))
            }
            Icmpv4DestUnreachCode::Port => Some(("port_unreachable", Severity::Info)),
            Icmpv4DestUnreachCode::Net | Icmpv4DestUnreachCode::DestNetworkUnknown => {
                Some(("network_unreachable", Severity::Warning))
            }
            Icmpv4DestUnreachCode::NetworkProhibited
            | Icmpv4DestUnreachCode::HostProhibited
            | Icmpv4DestUnreachCode::CommunicationProhibited => {
                Some(("administratively_prohibited", Severity::Warning))
            }
            _ => Some(("dest_unreachable_other", Severity::Info)),
        },
        IcmpType::V6(Icmpv6Type::DestinationUnreachable { code, .. }) => match code {
            Icmpv6DestUnreachCode::AddressUnreachable => {
                Some(("host_unreachable", Severity::Warning))
            }
            Icmpv6DestUnreachCode::PortUnreachable => Some(("port_unreachable", Severity::Info)),
            Icmpv6DestUnreachCode::NoRoute => Some(("network_unreachable", Severity::Warning)),
            Icmpv6DestUnreachCode::AdminProhibited
            | Icmpv6DestUnreachCode::RejectRouteToDestination
            | Icmpv6DestUnreachCode::SourceAddressFailedIngressPolicy => {
                Some(("administratively_prohibited", Severity::Warning))
            }
            _ => Some(("dest_unreachable_other", Severity::Info)),
        },
        _ => None,
    }
}

/// Add a packet's bytes to the right bucket based on the flow's
/// well-known protocol label. Falls back to `other_tcp` /
/// `other_udp` when neither endpoint port is recognised.
fn bandwidth_bucket<'a>(
    stats: &'a mut AppBandwidth,
    key: &FlowKey,
    is_tcp: bool,
) -> &'a mut AppBucket {
    if let Some(label) = key.protocol_label() {
        stats.by_app.entry(label).or_default()
    } else if is_tcp {
        &mut stats.other_tcp
    } else {
        &mut stats.other_udp
    }
}

fn print_bandwidth_report(
    stats: &AppBandwidth,
    resets: &TcpResetCount,
    icmp: &IcmpUnreachableCount,
) {
    println!("─── net_diagnostic ───");
    println!(
        "tcp_resets={} (zero_payload={})  icmp_unreachable: host={} port={} network={} prohibited={} other={}",
        resets.total,
        resets.zero_payload,
        icmp.host,
        icmp.port,
        icmp.network,
        icmp.prohibited,
        icmp.other,
    );

    // Stable sort by bytes desc so the chatty apps surface first.
    let mut rows: Vec<(&'static str, AppBucket)> =
        stats.by_app.iter().map(|(k, v)| (*k, *v)).collect();
    rows.push(("other/tcp", stats.other_tcp));
    rows.push(("other/udp", stats.other_udp));
    rows.sort_by_key(|row| std::cmp::Reverse(row.1.bytes));

    println!("{:<14} {:>14} {:>12}", "app", "bytes", "packets");
    for (app, bucket) in rows.iter().filter(|(_, b)| b.bytes > 0) {
        println!("{app:<14} {:>14} {:>12}", bucket.bytes, bucket.packets);
    }
    println!();
}

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
        // 3 protocols → 3 dispatch slots.
        .protocol::<Tcp>()
        .protocol::<Udp>()
        .protocol::<Icmp>()
        // 3 independent state slots — one per signal.
        .state::<AppBandwidth>()
        .state::<TcpResetCount>()
        .state::<IcmpUnreachableCount>()
        // ── ICMP Destination Unreachable ────────────────────
        .on_ctx::<Icmp>(|msg: &IcmpMessage, ctx: &mut Ctx<'_>| {
            let Some((code_label, severity)) = classify_unreachable(msg) else {
                return Ok(());
            };
            let ts = ctx.ts;
            // Split the borrow so we can bump the counter +
            // emit through the sink in one statement.
            let (counters, sink) = ctx.split_state_sink::<IcmpUnreachableCount>();
            match code_label {
                "host_unreachable" => counters.host += 1,
                "port_unreachable" => counters.port += 1,
                "network_unreachable" => counters.network += 1,
                "administratively_prohibited" => counters.prohibited += 1,
                _ => counters.other += 1,
            }
            sink.begin("IcmpUnreachable", severity, ts)
                .with("code", code_label)
                .with("family", icmp_family_str(msg))
                .emit();
            Ok(())
        })
        // ── TCP RESET alerts ────────────────────────────────
        .on_ctx::<FlowEnded<Tcp>>(|evt: &FlowEnded<Tcp>, ctx: &mut Ctx<'_>| {
            if evt.reason != EndReason::Rst {
                return Ok(());
            }
            let ts = ctx.ts;
            let total_bytes = evt.stats.bytes_initiator + evt.stats.bytes_responder;
            let zero_payload = total_bytes == 0;
            let counters = ctx.state_mut::<TcpResetCount>();
            counters.total += 1;
            if zero_payload {
                counters.zero_payload += 1;
            }
            ctx.sink_mut()
                .begin(
                    "TcpReset",
                    if zero_payload {
                        Severity::Info
                    } else {
                        Severity::Warning
                    },
                    ts,
                )
                .with("src", format!("{}", evt.key.a))
                .with("dst", format!("{}", evt.key.b))
                .with_metric("bytes_initiator", evt.stats.bytes_initiator as f64)
                .with_metric("bytes_responder", evt.stats.bytes_responder as f64)
                .with_metric("packets_initiator", evt.stats.packets_initiator as f64)
                .with_metric("packets_responder", evt.stats.packets_responder as f64)
                .emit();
            Ok(())
        })
        // ── Per-packet bandwidth (TCP + UDP) ────────────────
        // 0.22 R2: one flat FlowPacket handler branches on
        // `evt.proto` instead of two `FlowPacket<Tcp>` / `<Udp>`
        // handlers. (§2.9 replaces all of this with
        // `.on_bandwidth(...)`.)
        .on_ctx::<FlowPacket>(|evt: &FlowPacket, ctx: &mut Ctx<'_>| {
            let is_tcp = match evt.proto {
                L4Proto::Tcp => true,
                L4Proto::Udp => false,
                _ => return Ok(()), // ignore ICMP / other here
            };
            let stats = ctx.state_mut::<AppBandwidth>();
            bandwidth_bucket(stats, &evt.key, is_tcp).add(evt.len);
            Ok(())
        })
        // ── Periodic report ─────────────────────────────────
        .tick(Duration::from_secs(5), |_tick: &Tick, ctx: &mut Ctx<'_>| {
            // Read the two small Copy slots out by value, then
            // borrow the bandwidth map last. Sequential
            // `state_mut::<T>()` borrows are fine — each goes
            // out of scope before the next starts.
            let resets = *ctx.state_mut::<TcpResetCount>();
            let icmp = *ctx.state_mut::<IcmpUnreachableCount>();
            let stats = ctx.state_mut::<AppBandwidth>();
            print_bandwidth_report(stats, &resets, &icmp);
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_net_diagnostic: done");
    Ok(())
}

fn icmp_family_str(msg: &IcmpMessage) -> &'static str {
    match msg.ty {
        IcmpType::V4(_) => "v4",
        IcmpType::V6(_) => "v6",
        _ => "other",
    }
}
