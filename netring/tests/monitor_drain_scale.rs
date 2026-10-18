//! Review r2: the #216 source resolver looked a flow the batch ended up
//! with a linear scan, once per event / message of such a flow — O(N²)
//! for a sweep or shutdown drain ending N flows with a parser attached
//! (one `ParserClosed` per flow). 60 000 DNS flows at shutdown ran out the
//! default drain deadline and delivered no `FlowEnded` at all.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "dns"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use flowscope::extract::parse::test_frames::ipv4_udp;
use netring::monitor::Monitor;
use netring::protocol::builtin::{Dns, Udp};
use netring::protocol::event_typed::FlowEnded;
use tempfile::NamedTempFile;

fn dns_query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["a", "example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// `n` DNS queries, each from its own source address: `n` UDP flows, none
/// of which ends before the replay does.
fn pcap(n: usize) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    let q = dns_query();
    for i in 0..n {
        let src = [10, 1 + (i >> 16) as u8, (i >> 8) as u8, i as u8];
        let f = ipv4_udp(src, [10, 0, 0, 53], 40000, 53, &q);
        let ts = Duration::from_secs(1) + Duration::from_micros(i as u64);
        w.write_packet(&PcapPacket::new_owned(ts, f.len() as u32, f))
            .unwrap();
    }
    file
}

/// Replay `n` DNS flows; the shutdown drain (default deadline) ends them
/// all. Returns (`FlowEnded` delivered, time taken).
async fn drain(n: usize) -> (usize, Duration) {
    let file = pcap(n);
    let ended = Arc::new(AtomicUsize::new(0));
    let e = Arc::clone(&ended);
    let start = Instant::now();
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .protocol::<Dns>()
        .on::<FlowEnded<Udp>>(move |_: &FlowEnded<Udp>| {
            e.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    (ended.load(Ordering::Relaxed), start.elapsed())
}

/// The shutdown drain of 60 000 DNS flows delivers every `FlowEnded`
/// within the default drain deadline.
#[tokio::test(flavor = "current_thread")]
async fn shutdown_drain_of_60k_flows_delivers_every_flow_end() {
    const N: usize = 60_000;
    let (ended, took) = drain(N).await;
    assert_eq!(ended, N, "FlowEnded delivered by the drain (took {took:?})");
}

/// And it scales linearly: four times the flows takes well under the 16×
/// a quadratic resolver would (linear is ~4×; 10× leaves room for a busy
/// host).
#[tokio::test(flavor = "current_thread")]
async fn drain_time_grows_linearly_with_the_flow_count() {
    let (small_ended, small) = drain(15_000).await;
    let (big_ended, big) = drain(60_000).await;
    assert_eq!((small_ended, big_ended), (15_000, 60_000));
    assert!(
        big < small * 10,
        "15k flows: {small:?}, 60k flows: {big:?} — superlinear"
    );
}
