//! Live interfaces and pcap replays in **one** tagged session fan-in
//! (`MultiSessionStream::empty()` + `push_source`, 0.31.1) — the shape
//! of a tool that captures N interfaces in production and replays a
//! capture with `--read` in the lab, through the same event loop.
//!
//! ```bash
//! # two interfaces plus a capture, 10 s:
//! cargo run --example async_mixed_sources --features tokio,flow,parse,pcap -- lo eth0 --read trace.pcap --duration 10
//! # replay only (no privileges needed):
//! cargo run --example async_mixed_sources --features tokio,flow,parse,pcap -- --read trace.pcap
//! ```
//!
//! Every source hands back its tracker, live flow snapshots, dedup and
//! ring / file counters through `MultiSource`, so the final report is
//! the same code for a kernel source and a file.

use std::env;
use std::time::Duration;

use flowscope::{FlowSide, SessionParser, Timestamp};
use futures::StreamExt;
use netring::flow::SessionEvent;
use netring::flow::extract::FiveTuple;
use netring::{AsyncCapture, AsyncPcapSource, Dedup, MultiSessionStream, MultiSource};

/// The simplest useful `SessionParser`: one message per reassembled
/// chunk, per side. Real parsers do framing here.
#[derive(Default, Clone, Debug)]
struct ByteCounter;

#[derive(Debug)]
struct Counted {
    side: FlowSide,
    bytes: usize,
}

impl SessionParser for ByteCounter {
    type Message = Counted;

    fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Self::Message>) {
        out.push(Counted {
            side: FlowSide::Initiator,
            bytes: b.len(),
        });
    }

    fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Self::Message>) {
        out.push(Counted {
            side: FlowSide::Responder,
            bytes: b.len(),
        });
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ifaces = Vec::new();
    let mut files = Vec::new();
    let mut duration = Duration::from_secs(30);
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--read" => files.push(args.next().ok_or("--read needs a file")?),
            "--duration" => {
                duration =
                    Duration::from_secs(args.next().ok_or("--duration needs seconds")?.parse()?)
            }
            _ => ifaces.push(a),
        }
    }
    if ifaces.is_empty() && files.is_empty() {
        eprintln!("usage: async_mixed_sources [IFACE]... [--read FILE]... [--duration SECS]");
        return Ok(());
    }

    let mut fanin = MultiSessionStream::<FiveTuple, ByteCounter>::empty();
    for iface in &ifaces {
        let mut live = AsyncCapture::open(iface)?
            .flow_stream(FiveTuple::bidirectional())
            .session_stream(ByteCounter);
        if iface == "lo" {
            // Every loopback frame is seen twice (outgoing + host).
            live = live.with_dedup(Dedup::loopback());
        }
        let idx = fanin.push_source(iface.clone(), live);
        println!("[{idx}] live {iface}");
    }
    for file in &files {
        let replay = AsyncPcapSource::open(file)
            .await?
            .sessions(FiveTuple::bidirectional(), ByteCounter)
            // Captures rarely record the direction, so dedup on content.
            .with_dedup(Dedup::content(Duration::from_millis(1), 256));
        let idx = fanin.push_source(file.clone(), replay);
        println!("[{idx}] replay {file}");
    }

    let deadline = tokio::time::sleep(duration);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            ev = fanin.next() => match ev {
                None => break, // every source ended (replay only)
                Some(Err(e)) => eprintln!("error: {e}"),
                Some(Ok(t)) => {
                    let label = fanin.label(t.source_idx).unwrap_or("?");
                    match t.event {
                        SessionEvent::Started { key, .. } => println!("[{label}] started {key:?}"),
                        SessionEvent::Application { message, orientation, .. } => println!(
                            "[{label}] {:?} {:?} {} bytes",
                            message.side, orientation, message.bytes
                        ),
                        SessionEvent::Closed { key, reason, stats, .. } => println!(
                            "[{label}] closed {key:?} {reason} ({} pkts, gaps {}/{})",
                            stats.packets_initiator + stats.packets_responder,
                            stats.reassembly_gaps_initiator,
                            stats.reassembly_gaps_responder,
                        ),
                        SessionEvent::ParserClosed { key, reason, detail, .. } => {
                            println!("[{label}] parser closed {key:?} {reason} {detail:?}")
                        }
                        _ => {}
                    }
                }
            },
        }
        if fanin.alive_sources() == 0 {
            break;
        }
    }

    println!("\n== per-source report ==");
    for idx in 0..fanin.len() as u16 {
        let label = fanin.label(idx).unwrap_or("?");
        let src: &dyn MultiSource<FiveTuple> = fanin.source(idx).expect("in range");
        let t = src.tracker_stats();
        let dedup = src
            .dedup()
            .map(|d| format!("{} of {} dropped", d.dropped(), d.seen()))
            .unwrap_or_else(|| "no dedup".into());
        let input = match (src.capture_stats(), src.packets_read()) {
            (Some(Ok(s)), _) => format!("ring: {} pkts, {} drops", s.packets, s.drops),
            (Some(Err(e)), _) => format!("ring stats error: {e}"),
            (None, Some(n)) => format!("file: {n} frames read"),
            (None, None) => "no input counters".into(),
        };
        println!(
            "[{idx}] {label}: alive={:?} flows created={} ended={} live={} unmatched={} | {input} | {dedup}",
            fanin.is_alive(idx).unwrap_or(false),
            t.flows_created,
            t.flows_ended,
            src.active_flows(),
            t.packets_unmatched,
        );
        for (key, stats) in src.snapshot_flow_stats() {
            println!(
                "      live {key:?}: {}/{} pkts, rexmit {}/{}",
                stats.packets_initiator,
                stats.packets_responder,
                stats.retransmits_initiator,
                stats.retransmits_responder
            );
        }
    }
    Ok(())
}
