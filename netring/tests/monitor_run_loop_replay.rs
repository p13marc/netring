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

use std::sync::atomic::{AtomicUsize, Ordering};
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

/// `HandlerErrorPolicy::Isolate` covers tick handlers too: an `Err`
/// from a `.tick(..)` closure or an `.on::<Tick>` handler is counted
/// and the monitor keeps running (it used to stop the run).
#[tokio::test(flavor = "current_thread")]
async fn isolate_policy_covers_tick_handlers() {
    use netring::monitor::HandlerErrorPolicy;
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::Tick;
    let frames: Vec<_> = (1..=5)
        .map(|t| {
            (
                Duration::from_secs(t),
                ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"query"),
            )
        })
        .collect();
    let file = pcap(&frames);
    let (closure_ticks, typed_ticks) = (Arc::new(Mutex::new(0)), Arc::new(Mutex::new(0)));
    let (c, t) = (Arc::clone(&closure_ticks), Arc::clone(&typed_ticks));
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .tick_ctx(Duration::from_secs(1), move |_ctx: &mut Ctx<'_>| {
            *c.lock().unwrap() += 1;
            Err(netring::Error::Config("tick handler failed".into()))
        })
        .on::<Tick>(move |_t: &Tick| {
            *t.lock().unwrap() += 1;
            Err(netring::Error::Config("typed tick handler failed".into()))
        })
        .build()
        .unwrap();
    let health = monitor.health();
    monitor
        .replay()
        .await
        .expect("Isolate keeps the monitor running");
    // Due at 2, 3, 4, 5 s.
    assert_eq!(*closure_ticks.lock().unwrap(), 4);
    assert_eq!(*typed_ticks.lock().unwrap(), 4);
    assert_eq!(health.handler_errors(), 8);
}

/// With `catch_handler_panics`, a panicking `.tick(..)` closure is a
/// `HandlerPanic` error like a panicking `.on::<E>` handler — isolated
/// under `Isolate` instead of unwinding the run loop.
#[tokio::test(flavor = "current_thread")]
async fn catch_handler_panics_covers_tick_closures() {
    use netring::monitor::HandlerErrorPolicy;
    use netring::protocol::builtin::Udp;
    let frames: Vec<_> = (1..=5)
        .map(|t| {
            (
                Duration::from_secs(t),
                ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"query"),
            )
        })
        .collect();
    let file = pcap(&frames);
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .catch_handler_panics(true)
        .tick_ctx(Duration::from_secs(1), |_ctx: &mut Ctx<'_>| {
            panic!("tick closure panicked")
        })
        .build()
        .unwrap();
    let health = monitor.health();
    monitor
        .replay()
        .await
        .expect("the panic is caught and isolated");
    assert_eq!(health.handler_errors(), 4);
}

/// Under the default `Propagate` policy a tick handler error still
/// stops the monitor.
#[tokio::test(flavor = "current_thread")]
async fn propagate_policy_stops_on_a_tick_handler_error() {
    use netring::protocol::builtin::Udp;
    let frames: Vec<_> = (1..=5)
        .map(|t| {
            (
                Duration::from_secs(t),
                ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"query"),
            )
        })
        .collect();
    let file = pcap(&frames);
    let res = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .tick_ctx(Duration::from_secs(1), |_ctx: &mut Ctx<'_>| {
            Err(netring::Error::Config("tick handler failed".into()))
        })
        .build()
        .unwrap()
        .replay()
        .await;
    assert!(res.is_err());
}

/// An ICMPv4 port-unreachable (192.0.2.2 → 192.0.2.1) quoting a UDP
/// datagram 10.0.0.1:12345 → 10.0.0.2:53.
#[cfg(feature = "icmp")]
fn icmp_port_unreachable() -> Vec<u8> {
    use etherparse::{Ethernet2Header, IpNumber, Ipv4Header};
    let mut inner = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
    inner.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    inner.extend_from_slice(&12345u16.to_be_bytes());
    inner.extend_from_slice(&53u16.to_be_bytes());
    inner.extend_from_slice(&[0, 8, 0, 0]);
    let mut icmp = vec![3u8, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&inner);
    let ip = Ipv4Header::new(
        icmp.len() as u16,
        64,
        IpNumber::ICMP,
        [192, 0, 2, 2],
        [192, 0, 2, 1],
    )
    .unwrap();
    let eth = Ethernet2Header {
        destination: [2u8; 6],
        source: [1u8; 6],
        ether_type: etherparse::EtherType::IPV4,
    };
    let mut frame = Vec::new();
    eth.write(&mut frame).unwrap();
    ip.write(&mut frame).unwrap();
    frame.extend_from_slice(&icmp);
    frame
}

/// Declaring a protocol twice — explicitly, or through sugar that
/// declares it for you — installs one parser slot, not two: every
/// message used to be delivered once per declaration.
#[cfg(feature = "icmp")]
#[tokio::test(flavor = "current_thread")]
async fn redeclared_protocol_delivers_each_message_once() {
    use netring::protocol::builtin::Icmp;
    use netring::protocol::event_typed::IcmpError;
    let file = pcap(&timed(vec![icmp_port_unreachable()]));
    let (errors, raw) = (Arc::new(Mutex::new(0)), Arc::new(Mutex::new(0)));
    let (e, r) = (Arc::clone(&errors), Arc::clone(&raw));
    Monitor::builder()
        .pcap_source(file.path())
        .all_l4()
        .protocol::<Icmp>()
        .on_icmp_error(move |_err: &IcmpError, _ctx: &mut Ctx<'_>| {
            *e.lock().unwrap() += 1;
            Ok(())
        })
        .on::<Icmp>(move |_m: &flowscope::icmp::IcmpMessage| {
            *r.lock().unwrap() += 1;
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(*errors.lock().unwrap(), 1);
    assert_eq!(*raw.lock().unwrap(), 1);
}

/// A DNS query for `example.test` A, 10.0.0.1:5353 → 10.0.0.2:53.
#[cfg(feature = "dns")]
fn dns_query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07example\x04test\x00");
    q.extend_from_slice(&[0, 1, 0, 1]);
    ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &q)
}

/// Same for sugar that auto-declares a parser: `on_dns` then an
/// explicit `.protocol::<Dns>()` is one DNS slot.
#[cfg(feature = "dns")]
#[tokio::test(flavor = "current_thread")]
async fn on_dns_then_protocol_dns_delivers_each_message_once() {
    use netring::protocol::builtin::Dns;
    let file = pcap(&timed(vec![dns_query()]));
    let seen = Arc::new(Mutex::new(0));
    let s = Arc::clone(&seen);
    Monitor::builder()
        .pcap_source(file.path())
        .on_dns(move |v, _ctx| {
            if matches!(v.message, flowscope::dns::DnsMessage::Query(_)) {
                *s.lock().unwrap() += 1;
            }
            Ok(())
        })
        .protocol::<Dns>()
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), 1);
}

/// Two UDP flows: 10.0.0.1:5000 at t = 1 s (idle-ended by the sweep
/// the second drives) and 10.0.0.1:6000 at t = 200 s (ended at EOF).
fn two_udp_flows() -> Vec<(Duration, Vec<u8>)> {
    [(5000, 1), (6000, 200)]
        .into_iter()
        .map(|(sport, t)| {
            (
                Duration::from_secs(t),
                ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], sport, 53, b"query"),
            )
        })
        .collect()
}

/// A callback that panics on its first call and counts every call.
fn panics_once(calls: &AtomicUsize) {
    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
        panic!("first call panics");
    }
}

/// A caught panic in an `on_analyzed_flow` handler must not poison the
/// handler list: the next flow's handlers still run (every later event
/// used to fail on the poisoned lock).
#[tokio::test(flavor = "current_thread")]
async fn panicking_analyzed_flow_handler_does_not_poison_later_flows() {
    use netring::monitor::HandlerErrorPolicy;
    let file = pcap(&two_udp_flows());
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .catch_handler_panics(true)
        .flow_analysis()
        .on_analyzed_flow(move |_af, _ctx| panics_once(&c))
        .build()
        .unwrap();
    let health = monitor.health();
    monitor.replay().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(health.handler_errors(), 1);
}

struct NoScore;

impl netring::anomaly::DetectorScore for NoScore {
    fn kind(&self) -> flowscope::DetectorKind {
        flowscope::DetectorKind::Other("none")
    }
    fn into_anomaly(self, ts: flowscope::Timestamp) -> flowscope::OwnedAnomaly {
        flowscope::OwnedAnomaly::new(
            flowscope::DetectorKind::Other("none"),
            flowscope::event::Severity::Info,
            ts,
        )
    }
}

/// Same for a `pattern_detector!` whose body panics: its detector
/// mutex must not turn every later event into a panic.
#[tokio::test(flavor = "current_thread")]
async fn panicking_pattern_detector_does_not_poison_later_events() {
    use netring::monitor::HandlerErrorPolicy;
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::FlowStarted;
    let file = pcap(&two_udp_flows());
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let det = netring::pattern_detector! {
        name: "PanicsOnce",
        event: FlowStarted<Udp>,
        detector: 0u32,
        feed: |_evt, det| {
            *det += 1;
            panics_once(&c);
        },
        verdict: |_evt, _det| None::<NoScore>,
    };
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .catch_handler_panics(true)
        .detect(det)
        .build()
        .unwrap();
    let health = monitor.health();
    monitor.replay().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(health.handler_errors(), 1);
}

/// A DNS response 10.0.0.2:53 → 10.0.0.1:5353 answering
/// `example.test` A with `ip`.
#[cfg(feature = "dns")]
fn dns_response(id: u16, ip: [u8; 4]) -> Vec<u8> {
    let mut r = id.to_be_bytes().to_vec();
    r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    r.extend_from_slice(b"\x07example\x04test\x00");
    r.extend_from_slice(&[0, 1, 0, 1]);
    r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    r.extend_from_slice(&ip);
    ipv4_udp([10, 0, 0, 2], [10, 0, 0, 1], 53, 5353, &r)
}

/// Same for an `on_name` handler.
#[cfg(feature = "dns")]
#[tokio::test(flavor = "current_thread")]
async fn panicking_on_name_handler_does_not_poison_later_names() {
    use netring::monitor::HandlerErrorPolicy;
    let file = pcap(&timed(vec![
        dns_response(1, [192, 0, 2, 10]),
        dns_response(2, [192, 0, 2, 11]),
    ]));
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .catch_handler_panics(true)
        .name_map()
        .on_name(move |_ip, _claim, _ctx| panics_once(&c))
        .build()
        .unwrap();
    let health = monitor.health();
    monitor.replay().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(health.handler_errors(), 1);
}

/// Readiness ends with the run: `is_ready()` is true while the loop
/// services its source and false once it has returned (it used to stay
/// true forever), whether it ended cleanly or with an error.
#[tokio::test(flavor = "current_thread")]
async fn health_is_not_ready_after_the_run_returns() {
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::FlowStarted;
    let file = pcap(&two_udp_flows());
    let ready_during = Arc::new(Mutex::new(Vec::new()));
    let r = Arc::clone(&ready_during);
    let health_cell = Arc::new(Mutex::new(None::<netring::monitor::MonitorHealth>));
    let h = Arc::clone(&health_cell);
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>| {
            let ready = h.lock().unwrap().as_ref().unwrap().is_ready();
            r.lock().unwrap().push(ready);
            Ok(())
        })
        .build()
        .unwrap();
    let health = monitor.health();
    *health_cell.lock().unwrap() = Some(health.clone());
    assert!(!health.is_ready(), "not ready before the run");
    monitor.replay().await.unwrap();
    assert_eq!(*ready_during.lock().unwrap(), vec![true, true]);
    assert!(!health.is_ready(), "not ready once the run returned");

    // An error exit too.
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(|_e: &FlowStarted<Udp>| Err(netring::Error::Config("stop".into())))
        .build()
        .unwrap();
    let health = monitor.health();
    assert!(monitor.replay().await.is_err());
    assert!(!health.is_ready());
}

/// A zero period is a build error, not a panic when the live loop arms
/// its interval.
#[test]
fn zero_periods_are_rejected_at_build() {
    use netring::protocol::builtin::Udp;
    let base = || {
        Monitor::builder()
            .pcap_source("unused.pcap")
            .protocol::<Udp>()
    };
    let cases = [
        (
            "tick",
            base().tick_ctx(Duration::ZERO, |_ctx: &mut Ctx<'_>| Ok(())),
        ),
        ("tick", base().report(Duration::ZERO, |_snap| Ok(()))),
        (
            "on_capture_stats",
            base().on_capture_stats(Duration::ZERO, |_t, _ctx| Ok(())),
        ),
        (
            "export_active_timeout",
            base().export_active_timeout(Duration::ZERO),
        ),
    ];
    for (what, builder) in cases {
        let err = builder.build().expect_err(what).to_string();
        assert!(
            err.contains(what) && err.contains("non-zero period"),
            "{what}: {err}"
        );
    }
}

/// Durations too long to add to an `Instant` mean "never", not an
/// overflow panic: a `Duration::MAX` drain timeout or tick period on
/// replay.
#[tokio::test(flavor = "current_thread")]
async fn huge_durations_do_not_overflow_on_replay() {
    use netring::protocol::builtin::Udp;
    let file = pcap(&two_udp_flows());
    let ticks = Arc::new(AtomicUsize::new(0));
    let t = Arc::clone(&ticks);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .drain_timeout(Duration::MAX)
        .tick_ctx(Duration::MAX, move |_ctx: &mut Ctx<'_>| {
            t.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(ticks.load(Ordering::SeqCst), 0);
}

/// `run_for(Duration::MAX)` runs with no deadline instead of panicking
/// on `Instant + Duration::MAX`. Cap-free: the interface doesn't exist,
/// so the run fails opening it — after the deadline arithmetic.
#[tokio::test(flavor = "current_thread")]
async fn run_for_duration_max_does_not_overflow() {
    use netring::protocol::builtin::Udp;
    let res = Monitor::builder()
        .interface("nrm-missing0")
        .protocol::<Udp>()
        .build()
        .unwrap()
        .run_for(Duration::MAX)
        .await;
    assert!(res.is_err(), "the missing interface fails the open");
}

/// `SourceIdx` is a `u8`: more than 256 capture sources is a build
/// error (source 256 used to wrap to `SourceIdx(0)`).
#[test]
fn more_than_256_capture_sources_is_a_build_error() {
    use netring::protocol::builtin::Udp;
    let build = |n: usize| {
        Monitor::builder()
            .interfaces(vec!["lo"; n])
            .protocol::<Udp>()
            .build()
    };
    assert_eq!(build(256).unwrap().capture_sources().len(), 256);
    let Err(err) = build(257) else {
        panic!("257 capture sources built");
    };
    let err = err.to_string();
    assert!(err.contains("256") && err.contains("257"), "{err}");
}

/// Counts handler invocations by name.
#[derive(Clone, Default)]
struct Calls(Arc<Mutex<std::collections::BTreeMap<&'static str, usize>>>);

impl Calls {
    fn hit(&self, name: &'static str) {
        *self.0.lock().unwrap().entry(name).or_default() += 1;
    }
    fn get(&self, name: &'static str) -> usize {
        self.0.lock().unwrap().get(name).copied().unwrap_or(0)
    }
}

/// An effect handler that counts its calls and emits nothing.
fn counting_effect<P>(
    calls: &Calls,
    name: &'static str,
) -> impl Fn(
    &P,
    &Ctx<'_>,
) -> std::future::Ready<netring::error::Result<netring::monitor::effect::Effects>>
+ Send
+ Sync
+ 'static {
    let calls = calls.clone();
    move |_p: &P, _ctx: &Ctx<'_>| {
        calls.hit(name);
        std::future::ready(Ok(netring::monitor::effect::Effects::none()))
    }
}

/// An async handler that counts its calls.
fn counting_async<P>(
    calls: &Calls,
    name: &'static str,
) -> impl Fn(&P) -> std::future::Ready<netring::error::Result<()>> + Send + Sync + 'static {
    let calls = calls.clone();
    move |_p: &P| {
        calls.hit(name);
        std::future::ready(Ok(()))
    }
}

/// `on_async` / `on_effect` handlers fire for parser messages — they
/// were only ever registered: L7 messages went through the sync pass
/// alone.
#[cfg(feature = "dns")]
#[tokio::test(flavor = "current_thread")]
async fn async_and_effect_handlers_receive_parser_messages() {
    use flowscope::dns::DnsMessage;
    use netring::protocol::builtin::Dns;
    let file = pcap(&timed(vec![
        dns_query(),
        dns_response(0x1234, [192, 0, 2, 10]),
    ]));
    let calls = Calls::default();
    let c = calls.clone();
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Dns>()
        .on::<Dns>(move |_m: &DnsMessage| {
            c.hit("sync");
            Ok(())
        })
        .on_async::<Dns, _>(counting_async::<DnsMessage>(&calls, "async"))
        .on_effect::<Dns>(counting_effect::<DnsMessage>(&calls, "effect"))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert!(calls.get("sync") >= 2, "query + response");
    assert_eq!(calls.get("async"), calls.get("sync"));
    assert_eq!(calls.get("effect"), calls.get("sync"));
}

/// Same for the ICMP slot's two message types.
#[cfg(feature = "icmp")]
#[tokio::test(flavor = "current_thread")]
async fn async_and_effect_handlers_receive_icmp_messages_and_errors() {
    use netring::protocol::builtin::Icmp;
    use netring::protocol::event_typed::IcmpError;
    let file = pcap(&timed(vec![icmp_port_unreachable()]));
    let calls = Calls::default();
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Icmp>()
        .on_async::<Icmp, _>(counting_async::<flowscope::icmp::IcmpMessage>(
            &calls,
            "msg async",
        ))
        .on_effect::<Icmp>(counting_effect::<flowscope::icmp::IcmpMessage>(
            &calls,
            "msg effect",
        ))
        .on_async::<IcmpError, _>(counting_async::<IcmpError>(&calls, "err async"))
        .on_effect::<IcmpError>(counting_effect::<IcmpError>(&calls, "err effect"))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    for name in ["msg async", "msg effect", "err async", "err effect"] {
        assert_eq!(calls.get(name), 1, "{name}");
    }
}

/// `on_effect::<Tick>` handlers fire on ticks (only the sync and async
/// passes ran).
#[tokio::test(flavor = "current_thread")]
async fn effect_handlers_receive_ticks() {
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::Tick;
    let frames: Vec<_> = (1..=5)
        .map(|t| {
            (
                Duration::from_secs(t),
                ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"query"),
            )
        })
        .collect();
    let file = pcap(&frames);
    let calls = Calls::default();
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .tick_ctx(Duration::from_secs(1), |_ctx: &mut Ctx<'_>| Ok(()))
        .on_effect::<Tick>(counting_effect::<Tick>(&calls, "tick"))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(calls.get("tick"), 4, "due at 2, 3, 4, 5 s");
}

/// HTTP request split in two reversed segments with a 16-byte memcap:
/// the HTTP parser's initiator side stops (see `monitor_parser_routing`).
#[cfg(feature = "http")]
fn http_flow_with_reversed_request() -> Vec<Vec<u8>> {
    const REQ: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n";
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let (c, s, m) = ([10, 0, 0, 1], [10, 0, 0, 2], [0u8; 6]);
    let (ci, si) = (100u32, 900u32);
    let (head, tail) = REQ.split_at(10);
    let cend = ci + 1 + REQ.len() as u32;
    let send = si + 1 + RESP.len() as u32;
    vec![
        ipv4_tcp(m, m, c, s, 40000, 80, ci, 0, 0x02, &[]),
        ipv4_tcp(m, m, s, c, 80, 40000, si, ci + 1, 0x12, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x10, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 11, si + 1, 0x18, tail),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x18, head),
        ipv4_tcp(m, m, s, c, 80, 40000, si + 1, cend, 0x18, RESP),
        ipv4_tcp(m, m, c, s, 40000, 80, cend, send, 0x11, &[]),
        ipv4_tcp(m, m, s, c, 80, 40000, send, cend + 1, 0x11, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, cend + 1, send + 1, 0x10, &[]),
    ]
}

/// `on_effect` handlers fire for parser closes and side stops — of the
/// parser's protocol (`ParserClosed<Http>`) and of the transport
/// (`ParserSideStopped<Tcp>`, which the effect pass had no arm for).
#[cfg(feature = "http")]
#[tokio::test(flavor = "current_thread")]
async fn effect_handlers_receive_parser_events() {
    use flowscope::MemcapPolicy;
    use netring::protocol::builtin::{Http, Tcp};
    use netring::protocol::event_typed::{ParserClosed, ParserSideStopped};
    let file = pcap(&timed(http_flow_with_reversed_request()));
    let calls = Calls::default();
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .protocol::<Http>()
        .reassembly_memcap(16, MemcapPolicy::PassThrough)
        .on_effect::<ParserClosed<Http>>(counting_effect::<ParserClosed<Http>>(
            &calls,
            "closed http",
        ))
        .on_effect::<ParserSideStopped<Http>>(counting_effect::<ParserSideStopped<Http>>(
            &calls,
            "side http",
        ))
        .on_effect::<ParserSideStopped<Tcp>>(counting_effect::<ParserSideStopped<Tcp>>(
            &calls, "side tcp",
        ))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(calls.get("side http"), 1);
    assert_eq!(calls.get("side tcp"), 1);
    assert_eq!(calls.get("closed http"), 1);
}
