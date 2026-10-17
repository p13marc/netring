//! Run-loop regressions caught on replay (0.31.2 audit): broadcast
//! subscriber lifetime, per-flow state vs. idle sweeps, the handler
//! error policy on ticks, protocol idempotence, async/effect handlers
//! for parser messages, and handler-list poisoning.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[allow(unused_imports)]
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
#[allow(unused_imports)]
use netring::ctx::Ctx;
use netring::monitor::Monitor;
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

/// Frames 1 ms apart from t = 1 s.
#[allow(dead_code)]
fn timed(frames: Vec<Vec<u8>>) -> Vec<(Duration, Vec<u8>)> {
    frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| (Duration::from_millis(1_000 + i as u64), f))
        .collect()
}

/// One HTTP/1.1 exchange on 10.0.0.1:40000 → 10.0.0.2:80: handshake,
/// request, response, FIN exchange.
#[cfg(feature = "http")]
fn http_flow() -> Vec<Vec<u8>> {
    const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let (c, s, m) = ([10, 0, 0, 1], [10, 0, 0, 2], [0u8; 6]);
    let (ci, si) = (100u32, 900u32);
    let cend = ci + 1 + REQ.len() as u32;
    let send = si + 1 + RESP.len() as u32;
    vec![
        ipv4_tcp(m, m, c, s, 40000, 80, ci, 0, 0x02, &[]),
        ipv4_tcp(m, m, s, c, 80, 40000, si, ci + 1, 0x12, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x10, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x18, REQ),
        ipv4_tcp(m, m, s, c, 80, 40000, si + 1, cend, 0x18, RESP),
        ipv4_tcp(m, m, c, s, 40000, 80, cend, send, 0x11, &[]),
        ipv4_tcp(m, m, s, c, 80, 40000, send, cend + 1, 0x11, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, cend + 1, send + 1, 0x10, &[]),
    ]
}

/// The template `BroadcastSlotHandle` that `with_broadcast` keeps for
/// `subscribe()` is itself a subscriber: it must not stay registered
/// (and queue every message, unread) for the whole run.
#[cfg(feature = "http")]
#[tokio::test(flavor = "current_thread")]
async fn broadcast_template_is_not_a_subscriber_during_the_run() {
    use netring::protocol::builtin::{Http, Tcp};
    let file = pcap(&timed(http_flow()));
    let seen: Arc<Mutex<Vec<usize>>> = Arc::default();
    let stream_cell = Arc::new(Mutex::new(None::<netring::monitor::EventStream<_>>));
    let (s, cell) = (Arc::clone(&seen), Arc::clone(&stream_cell));
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .with_broadcast::<Http>()
        .on::<Http>(move |_msg: &flowscope::http::HttpMessage| {
            let guard = cell.lock().unwrap();
            let stream = guard.as_ref().expect("subscribed before the run");
            s.lock().unwrap().push(stream.subscribers());
            Ok(())
        })
        .build()
        .unwrap();
    *stream_cell.lock().unwrap() = Some(monitor.subscribe::<Http>().unwrap());
    monitor.replay().await.unwrap();
    // The dispatcher's slot + the user's stream; no third, never-drained
    // template queue growing with every message.
    assert_eq!(*seen.lock().unwrap(), vec![2, 2]);
    let mut stream = stream_cell.lock().unwrap().take().unwrap();
    let mut out = Vec::new();
    assert_eq!(
        stream.recv_many(&mut out, 16),
        2,
        "the user stream got both"
    );
}

#[derive(Default)]
struct Seen(u32);

/// An idle-ended flow's `FlowEnded` handlers still see its per-flow
/// state: the sweep frees state only after the events it produced
/// were dispatched (it used to free first, so a `flow_state` whose
/// TTL is no longer than the idle gap read back `T::default()`).
#[tokio::test(flavor = "current_thread")]
async fn idle_ended_flow_keeps_its_state_for_flow_ended() {
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::{FlowEnded, FlowStarted};
    let udp = |sport: u16, t: u64| {
        (
            Duration::from_secs(t),
            ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], sport, 53, b"query"),
        )
    };
    // Flow 5000 goes quiet after t = 3 s; the packet at t = 200 s
    // drives the sweep that idle-ends it (UDP idle timeout 60 s).
    let file = pcap(&[udp(5000, 1), udp(5000, 2), udp(5000, 3), udp(6000, 200)]);
    let ended: Arc<Mutex<Vec<(u16, u32)>>> = Arc::default();
    let e = Arc::clone(&ended);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .flow_state::<Seen>(Duration::from_secs(60))
        .on_ctx::<FlowStarted<Udp>>(|_e: &FlowStarted<Udp>, ctx: &mut Ctx<'_>| {
            ctx.flow_state_mut::<Seen>().expect("registered").0 = 42;
            Ok(())
        })
        .on_ctx::<FlowEnded<Udp>>(move |ev: &FlowEnded<Udp>, ctx: &mut Ctx<'_>| {
            let port = ev.key.a.port().max(ev.key.b.port());
            let v = ctx.flow_state_mut::<Seen>().expect("registered").0;
            e.lock().unwrap().push((port, v));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(*ended.lock().unwrap(), vec![(5000, 42), (6000, 42)]);
}
