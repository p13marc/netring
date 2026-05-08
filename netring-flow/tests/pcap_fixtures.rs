//! Integration tests driven by the pcap fixtures in `tests/data/`.
//!
//! Run with:
//!     cargo test -p netring-flow --test pcap_fixtures

use std::io::Cursor;

use netring_flow::extract::FiveTuple;
use netring_flow::{EndReason, FlowEvent, FlowTracker, L4Proto, PacketView, Timestamp};

use pcap_file::pcap::PcapReader;

const HTTP_SESSION: &[u8] = include_bytes!("data/http_session.pcap");
const DNS_QUERIES: &[u8] = include_bytes!("data/dns_queries.pcap");
const MIXED_SHORT: &[u8] = include_bytes!("data/mixed_short.pcap");

fn drive_tracker_to_completion(raw: &[u8]) -> Vec<FlowEvent<netring_flow::extract::FiveTupleKey>> {
    let mut reader = PcapReader::new(Cursor::new(raw)).expect("PcapReader::new");
    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut events = Vec::new();
    let mut last_ts = Timestamp::default();

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.expect("read packet");
        let ts = Timestamp::new(pkt.timestamp.as_secs() as u32, pkt.timestamp.subsec_nanos());
        last_ts = ts;
        let view = PacketView::new(&pkt.data, ts);
        events.extend(tracker.track(view));
    }

    // Force any lingering flows to end via a far-future sweep so
    // tests can assert on Ended events for unfinished flows.
    let far = Timestamp::new(last_ts.sec.saturating_add(86_400), 0);
    events.extend(tracker.sweep(far));
    events
}

#[test]
fn http_session_full_lifecycle() {
    let evts = drive_tracker_to_completion(HTTP_SESSION);

    let started_count = evts
        .iter()
        .filter(|e| matches!(e, FlowEvent::Started { .. }))
        .count();
    assert_eq!(started_count, 1, "expected exactly 1 Started event");

    let est = evts
        .iter()
        .filter(|e| matches!(e, FlowEvent::Established { .. }))
        .count();
    assert_eq!(est, 1, "TCP 3WHS should produce exactly 1 Established");

    let ended = evts
        .iter()
        .find_map(|e| match e {
            FlowEvent::Ended {
                reason, history, ..
            } => Some((*reason, *history)),
            _ => None,
        })
        .expect("flow should have ended (FIN sequence in fixture)");

    assert_eq!(ended.0, EndReason::Fin);
    // History string includes SYN (S/s), Data (D/d), FIN (F/f).
    let h = ended.1.as_str();
    assert!(
        h.contains('S') && h.contains('s') && h.contains('F') && h.contains('f'),
        "expected SsFf chars in history; got {h:?}"
    );
}

#[test]
fn dns_queries_parsed_as_udp_flows() {
    let evts = drive_tracker_to_completion(DNS_QUERIES);

    // The fixture has client/resolver pairs, plus a lone NXDOMAIN
    // and a lone unanswered query — possibly 1 bidirectional flow
    // (with bidirectional FiveTuple). Just assert "saw UDP flows".
    let udp_started = evts
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Started {
                    l4: Some(L4Proto::Udp),
                    ..
                }
            )
        })
        .count();
    assert!(
        udp_started >= 1,
        "expected ≥1 UDP flow Started; got {udp_started}"
    );

    // No TCP traffic in this fixture.
    let tcp_started = evts
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Started {
                    l4: Some(L4Proto::Tcp),
                    ..
                }
            )
        })
        .count();
    assert_eq!(tcp_started, 0, "DNS fixture should have no TCP flows");
}

#[test]
fn mixed_short_has_tcp_udp_and_icmp() {
    let evts = drive_tracker_to_completion(MIXED_SHORT);

    let mut by_proto = std::collections::HashMap::<L4Proto, usize>::new();
    for e in &evts {
        if let FlowEvent::Started { l4: Some(p), .. } = e {
            *by_proto.entry(*p).or_default() += 1;
        }
    }

    assert!(
        by_proto.get(&L4Proto::Tcp).copied().unwrap_or(0) >= 1,
        "expected TCP flow; got {by_proto:?}"
    );
    assert!(
        by_proto.get(&L4Proto::Udp).copied().unwrap_or(0) >= 1,
        "expected UDP flow; got {by_proto:?}"
    );
    assert!(
        by_proto.get(&L4Proto::Icmp).copied().unwrap_or(0) >= 1,
        "expected ICMP flow; got {by_proto:?}"
    );
}
