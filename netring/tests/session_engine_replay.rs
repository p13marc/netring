//! netring's session / datagram streams run flowscope's session engine
//! (0.31). Scenarios N1–N4 come from the des-capture report against
//! netring 0.30 (whose streams ignored parser poison, reassembly
//! overflow and reassembly stats); the rest pin the fixes found while
//! redesigning. Replayed from pcap files, so no capture privileges.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "pcap",
    feature = "parse"
))]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::{
    AnomalyKind, DatagramParser, EndReason, FlowEvent, FlowSide, FlowTrackerConfig, OverflowPolicy,
    ReassemblyStop, SessionParser, Timestamp,
};
use futures::StreamExt;
use netring::flow::SessionEvent;
use netring::{AsyncPcapSource, Dedup};
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::{DataLink, Endianness, TsResolution};

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const FIN: u8 = 0x01;

/// Client 10.0.0.1:40000 → server 10.0.0.2:9000: handshake, the given
/// (offset, payload) client segments, FIN exchange. 1 ms apart.
fn flow(segments: &[(u32, Vec<u8>)]) -> Vec<(Duration, Vec<u8>)> {
    let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let (cp, sp) = (40_000, 9_000);
    let (cisn, sisn) = (1000u32, 5000u32);
    let m = [0u8; 6];
    let mut v = vec![
        ipv4_tcp(m, m, c, s, cp, sp, cisn, 0, SYN, &[]),
        ipv4_tcp(m, m, s, c, sp, cp, sisn, cisn + 1, SYN | ACK, &[]),
        ipv4_tcp(m, m, c, s, cp, sp, cisn + 1, sisn + 1, ACK, &[]),
    ];
    let mut end = cisn + 1;
    for (off, payload) in segments {
        let seq = cisn + 1 + off;
        v.push(ipv4_tcp(
            m,
            m,
            c,
            s,
            cp,
            sp,
            seq,
            sisn + 1,
            PSH | ACK,
            payload,
        ));
        end = end.max(seq + payload.len() as u32);
    }
    v.push(ipv4_tcp(m, m, c, s, cp, sp, end, sisn + 1, FIN | ACK, &[]));
    v.push(ipv4_tcp(
        m,
        m,
        s,
        c,
        sp,
        cp,
        sisn + 1,
        end + 1,
        FIN | ACK,
        &[],
    ));
    v.push(ipv4_tcp(m, m, c, s, cp, sp, end + 1, sisn + 2, ACK, &[]));
    v.into_iter()
        .enumerate()
        .map(|(i, f)| (Duration::from_millis(1_000 + i as u64), f))
        .collect()
}

fn write_pcap(dir: &Path, name: &str, frames: &[(Duration, Vec<u8>)]) -> PathBuf {
    let path = dir.join(format!("{name}.pcap"));
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: u32::MAX,
        datalink: DataLink::ETHERNET,
        ts_resolution: TsResolution::NanoSecond,
        endianness: Endianness::native(),
    };
    let mut w = PcapWriter::with_header(std::fs::File::create(&path).unwrap(), header).unwrap();
    for (ts, f) in frames {
        w.write_packet(&PcapPacket::new_owned(*ts, f.len() as u32, f.clone()))
            .unwrap();
    }
    path
}

#[derive(Clone, Default)]
struct PoisonAfterFirstFeed {
    feeds: Arc<AtomicUsize>,
    poisoned: bool,
}

impl SessionParser for PoisonAfterFirstFeed {
    type Message = usize;
    fn feed_initiator(&mut self, bytes: &[u8], _: Timestamp, out: &mut Vec<usize>) {
        self.feeds.fetch_add(1, Ordering::SeqCst);
        self.poisoned = true;
        out.push(bytes.len());
    }
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<usize>) {
        self.feed_initiator(bytes, ts, out);
    }
    fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn poison_reason(&self) -> Option<&str> {
        self.poisoned.then_some("bad magic")
    }
}

#[derive(Clone, Default)]
struct CountBytes {
    bytes: Arc<AtomicUsize>,
}

impl SessionParser for CountBytes {
    type Message = ();
    fn feed_initiator(&mut self, bytes: &[u8], _: Timestamp, _: &mut Vec<()>) {
        self.bytes.fetch_add(bytes.len(), Ordering::SeqCst);
    }
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<()>) {
        self.feed_initiator(bytes, ts, out);
    }
}

async fn sessions<P>(
    path: &Path,
    cfg: FlowTrackerConfig,
    parser: P,
) -> Vec<SessionEvent<FiveTupleKey, P::Message>>
where
    P: SessionParser + Clone + Unpin,
    P::Message: Unpin,
{
    AsyncPcapSource::open(path)
        .await
        .unwrap()
        .flow_events(FiveTuple::bidirectional())
        .with_config(cfg)
        .session_stream(parser)
        .with_emit_anomalies(true)
        .map(|r| r.unwrap())
        .collect()
        .await
}

fn closes<M>(events: &[SessionEvent<FiveTupleKey, M>]) -> Vec<(EndReason, Option<String>)> {
    events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::ParserClosed { reason, detail, .. } => Some((*reason, detail.clone())),
            _ => None,
        })
        .collect()
}

fn ended<M>(events: &[SessionEvent<FiveTupleKey, M>]) -> Vec<(EndReason, flowscope::FlowStats)> {
    events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Closed { reason, stats, .. } => Some((*reason, stats.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn n1_poisoned_parser_is_closed_and_never_fed_again() {
    let dir = tempfile::tempdir().unwrap();
    let frames = flow(&[
        (0, vec![b'a'; 10]),
        (10, vec![b'b'; 10]),
        (20, vec![b'c'; 10]),
    ]);
    let path = write_pcap(dir.path(), "n1", &frames);
    let parser = PoisonAfterFirstFeed::default();
    let feeds = parser.feeds.clone();
    let events = sessions(&path, FlowTrackerConfig::default(), parser).await;

    assert_eq!(feeds.load(Ordering::SeqCst), 1);
    assert_eq!(
        closes(&events),
        vec![(EndReason::ParseError, Some("bad magic".into()))]
    );
    assert!(events.iter().any(|e| matches!(
        e,
        SessionEvent::FlowAnomaly {
            kind: AnomalyKind::SessionParseError { .. },
            ..
        }
    )));
    let ended = ended(&events);
    assert_eq!(ended.len(), 1, "one flow, never re-created");
    assert_eq!(ended[0].0, EndReason::Fin);
}

#[tokio::test(flavor = "current_thread")]
async fn n2_drop_flow_overflow_is_reported_and_does_not_wedge_silently() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_pcap(
        dir.path(),
        "n2",
        &flow(&[(0, vec![b'x'; 500]), (500, vec![b'y'; 10])]),
    );
    let mut cfg = FlowTrackerConfig::default();
    cfg.max_reassembler_buffer = Some(100);
    cfg.overflow_policy = OverflowPolicy::DropFlow;
    let parser = CountBytes::default();
    let bytes = parser.bytes.clone();
    let events = sessions(&path, cfg, parser).await;

    assert_eq!(bytes.load(Ordering::SeqCst), 0);
    let closes = closes(&events);
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].0, EndReason::BufferOverflow);
    assert!(events.iter().any(|e| matches!(
        e,
        SessionEvent::FlowAnomaly {
            kind: AnomalyKind::BufferOverflow {
                policy: OverflowPolicy::DropFlow,
                ..
            },
            ..
        }
    )));
    let ended = ended(&events);
    assert_eq!(ended.len(), 1);
    let (reason, stats) = &ended[0];
    assert_eq!(*reason, EndReason::Fin);
    assert_eq!(
        stats.reassembly_stop_initiator,
        Some(ReassemblyStop::Overflow)
    );
    assert_eq!(stats.reassembly_bytes_dropped_oversize_initiator, 500);
}

#[tokio::test(flavor = "current_thread")]
async fn n3_reassembly_stats_reach_closed_and_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    // In-order, a hole (10..20 never sent), data after it, and an
    // exact retransmit of the first segment.
    let path = write_pcap(
        dir.path(),
        "n3",
        &flow(&[
            (0, vec![b'a'; 10]),
            (20, vec![b'c'; 10]),
            (0, vec![b'a'; 10]),
        ]),
    );
    let events = sessions(&path, FlowTrackerConfig::default(), CountBytes::default()).await;
    let ended = ended(&events);
    let (_, stats) = &ended[0];
    assert!(stats.reassembler_high_watermark_initiator > 0);
    assert_eq!(stats.retransmits_initiator, 1);
    assert_eq!(stats.reassembly_gaps_initiator, 1);
    assert_eq!(stats.reassembly_gap_bytes_initiator, 10);
}

#[tokio::test(flavor = "current_thread")]
async fn a_missing_segment_is_a_reported_gap_not_a_silent_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_pcap(
        dir.path(),
        "gap",
        &flow(&[
            (0, vec![b'a'; 10]),
            (20, vec![b'c'; 10]),
            (30, vec![b'd'; 10]),
            (40, vec![b'e'; 10]),
        ]),
    );
    let parser = CountBytes::default();
    let bytes = parser.bytes.clone();
    let events = sessions(&path, FlowTrackerConfig::default(), parser).await;
    // The default parser response to a gap is to stop: the 10 bytes
    // before it were delivered, and the stop is explicit.
    assert_eq!(bytes.load(Ordering::SeqCst), 10);
    let closes = closes(&events);
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].0, EndReason::StreamGap);
    assert!(events.iter().any(|e| matches!(
        e,
        SessionEvent::FlowAnomaly {
            kind: AnomalyKind::StreamGap { bytes: 10, .. },
            ..
        }
    )));
}

#[tokio::test(flavor = "current_thread")]
async fn n4_pcap_replay_dedups_and_idles_out_on_packet_time() {
    let dir = tempfile::tempdir().unwrap();
    // Every frame twice (a raw `lo` dump), and a 10 s pause mid-flow.
    let mut frames = Vec::new();
    for (i, (ts, f)) in flow(&[(0, b"one".to_vec()), (3, b"two".to_vec())])
        .into_iter()
        .enumerate()
    {
        let ts = if i >= 4 {
            ts + Duration::from_secs(10)
        } else {
            ts
        };
        frames.push((ts, f.clone()));
        frames.push((ts, f));
    }
    let path = write_pcap(dir.path(), "n4", &frames);

    let mut cfg = FlowTrackerConfig::default();
    cfg.idle_timeout_tcp = Duration::from_secs(1);
    let source = AsyncPcapSource::open(&path).await.unwrap();
    let mut stream = source
        .flow_events(FiveTuple::bidirectional())
        .with_config(cfg)
        .with_dedup(Dedup::content(Duration::from_millis(1), 64));
    let mut started = 0;
    let mut ended = Vec::new();
    let mut packets = 0;
    while let Some(ev) = stream.next().await {
        match ev.unwrap() {
            FlowEvent::Started { .. } => started += 1,
            FlowEvent::Packet { .. } => packets += 1,
            FlowEvent::Ended { reason, .. } => ended.push(reason),
            _ => {}
        }
    }
    assert_eq!(packets, frames.len() / 2, "duplicates dropped");
    assert_eq!(stream.dedup().unwrap().dropped(), (frames.len() / 2) as u64);
    assert_eq!(started, 2, "the pause idles the flow out mid-replay");
    assert_eq!(ended[0], EndReason::IdleTimeout);
}

#[derive(Clone, Default)]
struct Sides;

impl DatagramParser for Sides {
    type Message = FlowSide;
    fn parse(&mut self, _: &[u8], side: FlowSide, _: Timestamp, out: &mut Vec<FlowSide>) {
        out.push(side);
    }
}

/// netring 0.30's DatagramStream derived `side` from address order;
/// a client with the higher address had every message mislabelled.
#[tokio::test(flavor = "current_thread")]
async fn datagram_side_is_relative_to_the_initiator() {
    let dir = tempfile::tempdir().unwrap();
    let (client, server) = ([10, 0, 0, 9], [10, 0, 0, 1]); // client > server
    let frames = vec![
        (
            Duration::from_secs(1),
            ipv4_udp(client, server, 5353, 53, b"query"),
        ),
        (
            Duration::from_secs(2),
            ipv4_udp(server, client, 53, 5353, b"answer"),
        ),
    ];
    let path = write_pcap(dir.path(), "udp", &frames);
    let sides: Vec<FlowSide> = AsyncPcapSource::open(&path)
        .await
        .unwrap()
        .datagrams(FiveTuple::bidirectional(), Sides)
        .filter_map(|e| async move {
            match e.unwrap() {
                SessionEvent::Application { message, .. } => Some(message),
                _ => None,
            }
        })
        .collect()
        .await;
    assert_eq!(sides, vec![FlowSide::Initiator, FlowSide::Responder]);
}
