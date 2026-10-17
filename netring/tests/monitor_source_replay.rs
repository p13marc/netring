//! #216: which capture source an event came from (`ctx.source`), on the
//! paths no packet drives — the idle sweep, ticks — and the capture leg
//! flowscope binds into the flow's stats.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::extract::parse::test_frames::ipv4_udp;
use netring::ctx::{Ctx, SourceIdx};
use netring::monitor::Monitor;
use netring::protocol::builtin::Udp;
use netring::protocol::event_typed::{FlowEnded, Tick};
use tempfile::NamedTempFile;

fn pcap(frames: &[(Duration, Vec<u8>)]) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (ts, f) in frames {
        w.write_packet(&PcapPacket::new_owned(*ts, f.len() as u32, f.clone()))
            .unwrap();
    }
    file
}

/// What the handlers saw: `(sport, ctx.source, stats.source_idx_forward)`
/// per `FlowEnded`, and `ctx.source` per tick.
#[derive(Default)]
struct Seen {
    ended: Vec<(u16, Option<SourceIdx>, Option<u32>)>,
    ticks: Vec<Option<SourceIdx>>,
}

/// Flow 5000 at t = 1 s is ended by the idle sweep the packet at t = 200 s
/// drives (UDP idle timeout 60 s); flow 6000 ends at EOF. Both are
/// replayed — source 0, flowscope leg 1. Ticks are no flow's: no source.
#[tokio::test(flavor = "current_thread")]
async fn swept_flows_and_ticks_report_their_source() {
    let udp = |sport: u16, t: u64| {
        (
            Duration::from_secs(t),
            ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], sport, 53, b"query"),
        )
    };
    let file = pcap(&[udp(5000, 1), udp(6000, 200)]);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (s1, s2) = (Arc::clone(&seen), Arc::clone(&seen));
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .on_ctx::<FlowEnded<Udp>>(move |e: &FlowEnded<Udp>, ctx: &mut Ctx<'_>| {
            let sport = e.key.a.port().max(e.key.b.port());
            s1.lock()
                .unwrap()
                .ended
                .push((sport, ctx.source, e.stats.source_idx_forward));
            Ok(())
        })
        .tick(
            Duration::from_secs(50),
            move |_t: &Tick, ctx: &mut Ctx<'_>| {
                s2.lock().unwrap().ticks.push(ctx.source);
                Ok(())
            },
        )
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    let mut ended = seen.ended.clone();
    ended.sort_by_key(|e| e.0);
    assert_eq!(
        ended,
        vec![
            (5000, Some(SourceIdx(0)), Some(1)),
            (6000, Some(SourceIdx(0)), Some(1)),
        ],
        "both flows: source 0, leg 1"
    );
    assert!(!seen.ticks.is_empty(), "ticks fired on packet time");
    assert!(
        seen.ticks.iter().all(Option::is_none),
        "a tick has no source: {:?}",
        seen.ticks
    );
}
