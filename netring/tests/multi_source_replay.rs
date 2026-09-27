//! `Multi*Stream::empty()` + `push_source` over pcap replay sources
//! (#176 / #177): tagged fan-in of heterogeneous sources, per-source
//! introspection through `MultiSource`, finished sources kept with their
//! final counters, sources added mid-stream. No capture privileges.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "pcap",
    feature = "parse"
))]

mod helpers;

use std::time::Duration;

use flowscope::extract::FiveTuple;
use flowscope::{DatagramParser, FlowSide, SessionParser, Timestamp};
use futures::StreamExt;
use helpers::pcap::{doubled, flow, flow_from, udp_flow, write_pcap};
use netring::flow::{FlowEvent, SessionEvent};
use netring::{AsyncPcapSource, Dedup, MultiDatagramStream, MultiFlowStream, MultiSessionStream};

#[derive(Clone, Default)]
struct Len;
impl SessionParser for Len {
    type Message = usize;
    fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<usize>) {
        out.push(b.len());
    }
    fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<usize>) {
        out.push(b.len());
    }
}

#[derive(Clone, Default)]
struct DgLen;
impl DatagramParser for DgLen {
    type Message = usize;
    fn parse(&mut self, b: &[u8], _: FlowSide, _: Timestamp, out: &mut Vec<usize>) {
        out.push(b.len());
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn two_replay_sources_fan_in_tag_and_finish() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let a = write_pcap(dir.path(), "a", &flow(&[(0, b"aaaa".to_vec())]));
        let b = write_pcap(dir.path(), "b", &flow_from(41_000, &[(0, b"bb".to_vec())]));
        let mut m = MultiSessionStream::<FiveTuple, Len>::empty()
            .with_source(
                "a",
                AsyncPcapSource::open(&a)
                    .await
                    .unwrap()
                    .sessions(FiveTuple::bidirectional(), Len),
            )
            .with_source(
                "b",
                AsyncPcapSource::open(&b)
                    .await
                    .unwrap()
                    .sessions(FiveTuple::bidirectional(), Len),
            );
        assert_eq!((m.len(), m.alive_sources()), (2, 2));

        let events: Vec<_> = tokio::time::timeout(Duration::from_secs(5), (&mut m).collect())
            .await
            .expect("both replays end, so the fan-in ends");
        let mut per_source = [0usize; 2];
        let mut data = [0usize; 2];
        for ev in &events {
            let ev = ev.as_ref().unwrap();
            per_source[ev.source_idx as usize] += 1;
            if let SessionEvent::Application { message, .. } = &ev.event {
                data[ev.source_idx as usize] += *message;
            }
        }
        assert!(per_source[0] >= 3 && per_source[1] >= 3, "{per_source:?}");
        assert_eq!(data, [4, 2], "each source's parser saw its own bytes");

        assert_eq!(m.alive_sources(), 0);
        assert_eq!(m.len(), 2);
        assert_eq!(m.label(0), Some("a"));
        assert_eq!(m.label(1), Some("b"));
        for (label, stats) in m.per_source_tracker_stats() {
            let stats =
                stats.unwrap_or_else(|| panic!("{label}: finished sources keep their stats"));
            assert_eq!((stats.flows_created, stats.flows_ended), (1, 1), "{label}");
        }
        assert_eq!(m.total_active_flows(), 0);
    });
}

#[test]
fn finished_source_keeps_final_stats() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let frames = doubled(&flow(&[(0, b"hello".to_vec())]), Duration::from_micros(50));
        let path = write_pcap(dir.path(), "dup", &frames);
        let mut m = MultiSessionStream::<FiveTuple, Len>::empty().with_source(
            "dup",
            AsyncPcapSource::open(&path)
                .await
                .unwrap()
                .sessions(FiveTuple::bidirectional(), Len)
                .with_dedup(Dedup::content(Duration::from_millis(1), 64)),
        );
        let n = tokio::time::timeout(Duration::from_secs(5), (&mut m).count())
            .await
            .unwrap();
        assert!(n >= 3);
        assert_eq!(m.is_alive(0), Some(false));
        let src = m.source(0).expect("kept after EOF");
        assert_eq!(src.packets_read(), Some(frames.len() as u64));
        assert_eq!(src.dedup().unwrap().dropped(), frames.len() as u64 / 2);
        assert!(src.capture_stats().is_none());
        assert_eq!(src.tracker_stats().flows_ended, 1);
        assert_eq!(src.active_flows(), 0);
        let cs = m.per_source_capture_stats();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].0, "dup");
        assert!(cs[0].1.is_none(), "a replay source has no kernel ring");
        assert_eq!(m.capture_stats().packets, 0);
        m.source_mut(0).unwrap().dedup_mut().unwrap().reset();
        assert_eq!(m.source(0).unwrap().dedup().unwrap().dropped(), 0);
    });
}

#[test]
fn mid_stream_snapshot_sees_live_flow() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let path = write_pcap(dir.path(), "a", &flow(&[(0, b"hello".to_vec())]));
        let mut m = MultiSessionStream::<FiveTuple, Len>::empty().with_source(
            "a",
            AsyncPcapSource::open(&path)
                .await
                .unwrap()
                .sessions(FiveTuple::bidirectional(), Len),
        );
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(5), m.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if matches!(ev.event, SessionEvent::Application { .. }) {
                break;
            }
        }
        assert_eq!(m.source(0).unwrap().active_flows(), 1);
        let snap = m.per_source_snapshot_flow_stats();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0].1.len(),
            1,
            "one live flow while the file is mid-way"
        );
        assert!(snap[0].1[0].1.packets_initiator >= 1);
        assert_eq!(m.total_active_flows(), 1);
    });
}

#[test]
fn push_source_after_first_events() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let a = write_pcap(dir.path(), "a", &flow(&[(0, b"aaaa".to_vec())]));
        let b = write_pcap(dir.path(), "b", &flow_from(41_000, &[(0, b"bb".to_vec())]));
        let mut m = MultiSessionStream::<FiveTuple, Len>::empty().with_source(
            "a",
            AsyncPcapSource::open(&a)
                .await
                .unwrap()
                .sessions(FiveTuple::bidirectional(), Len),
        );
        let first = m.next().await.unwrap().unwrap();
        assert_eq!(first.source_idx, 0);
        let idx = m.push_source(
            "b",
            AsyncPcapSource::open(&b)
                .await
                .unwrap()
                .sessions(FiveTuple::bidirectional(), Len),
        );
        assert_eq!(idx, 1);
        assert_eq!(m.alive_sources(), 2);
        let rest: Vec<_> = tokio::time::timeout(Duration::from_secs(5), (&mut m).collect())
            .await
            .unwrap();
        assert!(rest.iter().any(|e| e.as_ref().unwrap().source_idx == 1));
        assert_eq!(m.alive_sources(), 0);
    });
}

#[test]
fn flow_and_datagram_variants() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let tcp = write_pcap(dir.path(), "tcp", &flow(&[(0, b"hello".to_vec())]));
        let udp = write_pcap(dir.path(), "udp", &udp_flow(5353, 3));

        let mut flows = MultiFlowStream::<FiveTuple>::empty().with_source(
            "tcp",
            AsyncPcapSource::open(&tcp)
                .await
                .unwrap()
                .flow_events(FiveTuple::bidirectional()),
        );
        let events: Vec<_> = tokio::time::timeout(Duration::from_secs(5), (&mut flows).collect())
            .await
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e.as_ref().unwrap().event, FlowEvent::Ended { .. }))
        );
        assert_eq!(flows.source(0).unwrap().tracker_stats().flows_created, 1);
        assert_eq!(flows.source(0).unwrap().packets_read(), Some(7));

        let mut dgrams = MultiDatagramStream::<FiveTuple, DgLen>::empty().with_source(
            "udp",
            AsyncPcapSource::open(&udp)
                .await
                .unwrap()
                .datagrams(FiveTuple::bidirectional(), DgLen),
        );
        let events: Vec<_> = tokio::time::timeout(Duration::from_secs(5), (&mut dgrams).collect())
            .await
            .unwrap();
        let payload: usize = events
            .iter()
            .filter_map(|e| match &e.as_ref().unwrap().event {
                SessionEvent::Application { message, .. } => Some(*message),
                _ => None,
            })
            .sum();
        assert_eq!(payload, 3 * b"query".len());
        assert_eq!(dgrams.source(0).unwrap().tracker_stats().flows_created, 1);
        assert_eq!(dgrams.alive_sources(), 0);
    });
}
