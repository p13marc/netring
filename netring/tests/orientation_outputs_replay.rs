//! #215 / #217: every output names a flow from its **initiator**, and
//! IPFIX counts IP octets.
//!
//! One TCP connection, opened by 10.0.0.2:40000 towards 10.0.0.1:80 — the
//! initiator has the HIGHER address, so the address-sorted flow key puts
//! the server first (`key.a` = 10.0.0.1:80). Before 0.32 the flow exporter,
//! IPFIX, the IOC side label and the aggregate host pairs all reported the
//! server as the source, and IPFIX IE 1 / IE 85 carried the captured frame
//! length. No capture privileges.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

mod helpers;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use helpers::pcap::{flow_between, write_pcap};
use netring::anomaly::Severity;
use netring::anomaly::shipped_sinks::ChannelSink;
use netring::ctx::Ctx;
use netring::export::FlowRecord;
use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowEnded;

const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40_000);
const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80);

const PAYLOAD: &[u8] = b"GET /orientation-marker HTTP/1.1\r\nHost: example.com\r\n\r\n";

/// The capture, plus what the client put on the wire: (frames, L2 bytes,
/// IP bytes).
struct Capture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    client_frames: u64,
    client_wire_bytes: u64,
    client_ip_bytes: u64,
    total_ip_bytes: u64,
}

fn capture() -> Capture {
    let frames = flow_between(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        40_000,
        80,
        &[(0, PAYLOAD.to_vec())],
    );
    let (mut client_frames, mut client_wire_bytes, mut client_ip_bytes, mut total_ip_bytes) =
        (0, 0, 0, 0);
    for (_, f) in &frames {
        // Ethernet (14) + IPv4: the source address is at 14 + 12.
        let ip_len = (f.len() - 14) as u64;
        total_ip_bytes += ip_len;
        if f[26..30] == [10, 0, 0, 2] {
            client_frames += 1;
            client_wire_bytes += f.len() as u64;
            client_ip_bytes += ip_len;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = write_pcap(dir.path(), "orientation", &frames);
    Capture {
        _dir: dir,
        path,
        client_frames,
        client_wire_bytes,
        client_ip_bytes,
        total_ip_bytes,
    }
}

/// The flow records a capturing exporter receives.
async fn flow_records(cap: &Capture) -> Vec<FlowRecord> {
    let got: Arc<Mutex<Vec<FlowRecord>>> = Arc::default();
    let g = Arc::clone(&got);
    Monitor::builder()
        .pcap_source(&cap.path)
        .protocol::<Tcp>()
        .export_flows(move |r: &FlowRecord| g.lock().unwrap().push(r.clone()))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let got = got.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "{got:?}");
    got
}

/// (a) The flow record names the initiator and counts its wire bytes.
#[tokio::test(flavor = "current_thread")]
async fn a_flow_record_is_read_from_the_initiator() {
    let cap = capture();
    let r = &flow_records(&cap).await[0];
    assert_eq!(r.initiator, CLIENT);
    assert_eq!(r.responder, SERVER);
    assert_eq!(r.packets_initiator, cap.client_frames);
    assert_eq!(r.bytes_initiator, cap.client_wire_bytes);
    assert_eq!(r.ip_bytes_initiator, cap.client_ip_bytes);
    assert_eq!(r.total_ip_bytes(), cap.total_ip_bytes);
    // The key stays the flow's address-sorted identity.
    assert_eq!((r.key.a, r.key.b), (SERVER, CLIENT));
}

/// (b) IPFIX: source = the initiator; IE 1 / IE 85 are IP octets.
#[cfg(feature = "ipfix")]
#[tokio::test(flavor = "current_thread")]
async fn b_ipfix_source_is_the_initiator_and_counts_ip_octets() {
    let cap = capture();
    let ie = flow_records(&cap).await[0].to_ipfix_record();
    assert_eq!(
        (ie.octet_delta_count_initiator, ie.octet_total_count),
        (cap.client_ip_bytes, cap.total_ip_bytes),
        "IE 1 / IE 85 are IP octets"
    );
    assert_eq!(ie.source_ipv4_address, Some(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(ie.source_transport_port, 40_000);
    assert_eq!(
        ie.destination_ipv4_address,
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(ie.destination_transport_port, 80);
}

/// (c) An anomaly a `FlowEnded` handler keys with the event's flow key
/// reaches the EVE sink initiator-first.
#[cfg(feature = "eve-sink")]
#[tokio::test(flavor = "current_thread")]
async fn c_eve_anomaly_src_is_the_initiator() {
    use netring::anomaly::EveSink;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let cap = capture();
    let buf = SharedBuf::default();
    Monitor::builder()
        .pcap_source(&cap.path)
        .protocol::<Tcp>()
        .sink(EveSink::new(buf.clone(), Default::default()))
        .on_ctx::<FlowEnded<Tcp>>(|e: &FlowEnded<Tcp>, ctx: &mut Ctx<'_>| {
            ctx.emit("FlowDone", Severity::Info).with_key(&e.key).emit();
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["src_ip"], "10.0.0.2", "{v}");
    assert_eq!(v["src_port"], 40_000);
    assert_eq!(v["dest_ip"], "10.0.0.1");
}

/// (d) A host IOC on the server labels its side `dst`.
#[tokio::test(flavor = "current_thread")]
async fn d_ioc_on_the_responder_is_dst() {
    use netring::monitor::ioc::{IocSet, IocSetExt};

    let cap = capture();
    let (sink, mut rx) = ChannelSink::channel();
    let set = IocSet::new().ip("10.0.0.1".parse().unwrap());
    Monitor::builder()
        .pcap_source(&cap.path)
        .ioc(set)
        .sink(sink)
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let mut sides = Vec::new();
    while let Ok(a) = rx.try_recv() {
        if a.kind.as_str() == "ioc_match" {
            let side = a.observations.iter().find(|(k, _)| *k == "side");
            sides.push(side.map(|(_, v)| v.to_string()));
            // The anomaly reads the flow from its initiator too.
            assert_eq!(a.src_ip, Some(CLIENT.ip()));
        }
    }
    assert_eq!(sides, vec![Some("dst".to_string())]);
}

/// (e) YARA on the client's payload reports the initiator side (guard:
/// already right before 0.32).
#[cfg(feature = "yara")]
#[tokio::test(flavor = "current_thread")]
async fn e_yara_on_the_client_payload_is_the_initiator() {
    use netring::monitor::yara::{ScanDirection, YaraRules};
    use netring::protocol::FlowKey;

    let cap = capture();
    let rules =
        YaraRules::compile(r#"rule marker { strings: $m = "orientation-marker" condition: $m }"#)
            .unwrap();
    let got: Arc<Mutex<Vec<ScanDirection>>> = Arc::default();
    let g = Arc::clone(&got);
    Monitor::builder()
        .pcap_source(&cap.path)
        .protocol::<Tcp>()
        .yara(rules)
        .on_yara_match(move |_k: &FlowKey, m| g.lock().unwrap().push(m.direction))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(*got.lock().unwrap(), vec![ScanDirection::Initiator]);
}

/// (f) The aggregate traffic matrix keys a pair (initiator, responder).
#[tokio::test(flavor = "current_thread")]
async fn f_top_pairs_are_initiator_first() {
    use netring::monitor::aggregate::AggregateConfig;

    let cap = capture();
    let mut cfg = AggregateConfig::default();
    cfg.top_talkers = false;
    cfg.top_domains = false;
    cfg.top_sni = false;
    let seen: Arc<Mutex<Vec<(IpAddr, IpAddr)>>> = Arc::default();
    let s = Arc::clone(&seen);
    Monitor::builder()
        .pcap_source(&cap.path)
        .aggregate_with(cfg)
        .on_aggregate(std::time::Duration::from_millis(1), move |r| {
            s.lock()
                .unwrap()
                .extend(r.top_pairs(4).into_iter().map(|(p, _)| p));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "the report ticked with a pair");
    let want = (CLIENT.ip(), SERVER.ip());
    assert!(seen.iter().all(|p| *p == want), "{seen:?}");
}

/// (g) A `ChannelSink` owned anomaly carries the same src / dest.
#[tokio::test(flavor = "current_thread")]
async fn g_channel_anomaly_src_is_the_initiator() {
    let cap = capture();
    let (sink, mut rx) = ChannelSink::channel();
    Monitor::builder()
        .pcap_source(&cap.path)
        .protocol::<Tcp>()
        .sink(sink)
        .on_ctx::<FlowEnded<Tcp>>(|e: &FlowEnded<Tcp>, ctx: &mut Ctx<'_>| {
            ctx.emit("FlowDone", Severity::Info).with_key(&e.key).emit();
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let a = rx.try_recv().expect("one anomaly");
    assert_eq!(
        (a.src_ip, a.src_port, a.dest_ip, a.dest_port),
        (
            Some(CLIENT.ip()),
            Some(CLIENT.port()),
            Some(SERVER.ip()),
            Some(SERVER.port())
        )
    );
}

/// (h) Subscription filters read `src_*` from the initiator: a flow
/// filter on the client's port fires at flow end, a session filter on it
/// fires for the client's request.
#[tokio::test(flavor = "current_thread")]
async fn h_subscription_src_is_the_initiator() {
    use netring::monitor::subscription::flow;

    let cap = capture();
    let fired: Arc<Mutex<Vec<&'static str>>> = Arc::default();
    let f = Arc::clone(&fired);
    let b = Monitor::builder()
        .pcap_source(&cap.path)
        .protocol::<Tcp>()
        .subscribe(flow::<Tcp>().src_port(40_000).src_host(CLIENT.ip()).to(
            move |_e: &FlowEnded<Tcp>, _ctx| {
                f.lock().unwrap().push("flow");
                Ok(())
            },
        ));
    #[cfg(feature = "http")]
    let b = {
        use netring::monitor::subscription::session;
        use netring::protocol::builtin::Http;
        let f = Arc::clone(&fired);
        b.protocol::<Http>()
            .subscribe(session::<Http>().src_port(40_000).dst_port(80).to(
                move |_m: &flowscope::http::HttpMessage, _ctx| {
                    f.lock().unwrap().push("session");
                    Ok(())
                },
            ))
    };
    b.build().unwrap().replay().await.unwrap();
    let mut fired = fired.lock().unwrap().clone();
    fired.sort();
    #[cfg(feature = "http")]
    assert_eq!(fired, ["flow", "session"]);
    #[cfg(not(feature = "http"))]
    assert_eq!(fired, ["flow"]);
}
