//! `MonitorBuilder::dedup` (#178) on replay: a capture with every frame
//! twice (the `tcpdump -i lo` shape) doubles every count and reports
//! retransmits without it; content dedup restores single counts; the
//! direction-aware loopback profile is inert on a capture that recorded
//! no direction. No capture privileges.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "http"
))]

mod helpers;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::AnomalyKind;
use helpers::pcap::{doubled, flow_to, write_pcap};
use netring::Dedup;
use netring::monitor::Monitor;
use netring::protocol::builtin::{Http, Tcp};
use netring::protocol::event_typed::{AnyFlowAnomaly, FlowEnded, FlowPacket};

struct Outcome {
    /// One entry per `FlowEnded`: (packets, retransmits). Without dedup
    /// the duplicated FIN exchange even spawns a second, phantom flow on
    /// the same 5-tuple.
    flows: Vec<(u64, u64)>,
    flow_packets: usize,
    retransmit_anomalies: usize,
}

impl Outcome {
    fn packets(&self) -> u64 {
        self.flows.iter().map(|f| f.0).sum()
    }
    fn retransmits(&self) -> u64 {
        self.flows.iter().map(|f| f.1).sum()
    }
}

async fn replay(path: &std::path::Path, dedup: Option<Dedup>) -> Outcome {
    let ended = Arc::new(Mutex::new(Vec::new()));
    let flow_packets = Arc::new(AtomicUsize::new(0));
    let rexmit = Arc::new(AtomicUsize::new(0));
    let (e, fp, rx) = (ended.clone(), flow_packets.clone(), rexmit.clone());
    let mut b = Monitor::builder()
        .pcap_source(path)
        .protocol::<Tcp>()
        // A parser on the flow keeps it reassembled, which is where the
        // twin segments turn into retransmits.
        .protocol::<Http>()
        .on::<FlowEnded<Tcp>>(move |ev: &FlowEnded<Tcp>| {
            e.lock().unwrap().push((
                ev.stats.packets_initiator + ev.stats.packets_responder,
                ev.stats.retransmits_initiator + ev.stats.retransmits_responder,
            ));
            Ok(())
        })
        .on::<FlowPacket>(move |_: &FlowPacket| {
            fp.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        // Registering an anomaly handler turns anomalies on.
        .on::<AnyFlowAnomaly>(move |a: &AnyFlowAnomaly| {
            if matches!(a.kind, AnomalyKind::RetransmittedSegment { .. }) {
                rx.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });
    if let Some(d) = dedup {
        b = b.dedup(d);
    }
    b.build().unwrap().replay().await.unwrap();
    let flows = std::mem::take(&mut *ended.lock().unwrap());
    assert!(!flows.is_empty(), "the flow ended");
    Outcome {
        flows,
        flow_packets: flow_packets.load(Ordering::Relaxed),
        retransmit_anomalies: rexmit.load(Ordering::Relaxed),
    }
}

fn doubled_capture() -> (tempfile::TempDir, std::path::PathBuf, usize) {
    let dir = tempfile::tempdir().unwrap();
    let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    let single = flow_to(40_000, 80, &[(0, req)]);
    let frames = doubled(&single, Duration::from_micros(50));
    let path = write_pcap(dir.path(), "lo", &frames);
    (dir, path, single.len())
}

#[tokio::test(flavor = "current_thread")]
async fn duplicated_frames_double_counts_without_dedup() {
    let (_dir, path, n) = doubled_capture();
    let o = replay(&path, None).await;
    assert_eq!(o.packets(), 2 * n as u64, "every frame counted twice");
    assert_eq!(o.flow_packets, 2 * n, "every packet handler called twice");
    // One data segment in the capture, so its twin is one retransmit.
    assert!(
        o.retransmits() >= 1,
        "the twin data segment looks like a retransmit: flows {:?}, anomalies {}",
        o.flows,
        o.retransmit_anomalies
    );
    assert!(o.retransmit_anomalies >= 1);
    assert!(
        o.flows.len() >= 2,
        "the duplicated FIN exchange spawns a phantom flow: {:?}",
        o.flows
    );
}

#[tokio::test(flavor = "current_thread")]
async fn content_dedup_restores_single_counts() {
    let (_dir, path, n) = doubled_capture();
    let o = replay(&path, Some(Dedup::content(Duration::from_millis(1), 64))).await;
    assert_eq!(
        o.flows,
        vec![(n as u64, 0)],
        "one flow, every frame once, no retransmit"
    );
    assert_eq!(o.flow_packets, n);
    assert_eq!(o.retransmit_anomalies, 0);
}

/// `Dedup::loopback` only drops a twin seen in the *other* direction;
/// a legacy pcap records none, so the doubled capture still doubles
/// (the documented caveat: use `Dedup::content` on such input).
#[tokio::test(flavor = "current_thread")]
async fn loopback_profile_keeps_same_direction_twins() {
    let (_dir, path, n) = doubled_capture();
    let o = replay(&path, Some(Dedup::loopback())).await;
    assert_eq!(o.packets(), 2 * n as u64);
}
