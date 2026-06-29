//! 0.21 E.1: `Monitor::replay` from a synthetic pcap file.
//!
//! Builds a small UDP-only pcap, points the monitor at it, asserts
//! the FlowStarted<Udp> handler fired at least once.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::error::{BuildError, Error};
use netring::monitor::{HandlerErrorPolicy, Monitor};
use netring::protocol::builtin::Udp;
use netring::protocol::event_typed::FlowStarted;
use tempfile::NamedTempFile;

fn synthetic_udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut frame = Vec::with_capacity(total_len);
    // Ethernet
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4
    frame.push(0x45);
    frame.push(0x00);
    let ip_total = (20 + 8 + payload.len()) as u16;
    frame.extend_from_slice(&ip_total.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0, 0]);
    frame.push(64);
    frame.push(17); // UDP
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[10, 0, 0, 1]);
    frame.extend_from_slice(&[10, 0, 0, 2]);
    // UDP
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

fn write_synthetic_pcap() -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().expect("tempfile");
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: u32::MAX,
        datalink: pcap_file::DataLink::from(1),
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        endianness: pcap_file::Endianness::native(),
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).expect("writer");
    for i in 0..3u32 {
        let frame = synthetic_udp_frame(54321, 80, &[i as u8; 4]);
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_fires_flow_started_for_udp_traffic() {
    let pcap = write_synthetic_pcap();
    let started_count = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&started_count);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>| {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    // The 3 UDP packets share a flow → exactly one FlowStarted.
    assert!(
        started_count.load(Ordering::Relaxed) >= 1,
        "expected at least one FlowStarted<Udp> from replay"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_export_flows_emits_a_flow_record() {
    use std::sync::Mutex;

    use netring::export::FlowRecord;

    let pcap = write_synthetic_pcap();
    let collected: Arc<Mutex<Vec<FlowRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&collected);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        // A bare FnMut(&FlowRecord) is a FlowExporter (blanket impl).
        .export_flows(move |rec: &FlowRecord| sink.lock().unwrap().push(rec.clone()))
        .build()
        .expect("build with pcap_source + export_flows");

    monitor.replay().await.expect("replay completes");

    let records = collected.lock().unwrap();
    // The 3 UDP packets are one flow; on EOF the drain phase synthesizes a
    // FlowEnded, which the exporter turns into exactly one FlowRecord.
    assert_eq!(
        records.len(),
        1,
        "expected one flow record, got {records:?}"
    );
    let rec = &records[0];
    assert_eq!(rec.proto, flowscope::L4Proto::Udp);
    // 3 packets all from the initiator.
    assert_eq!(rec.total_packets(), 3, "rec = {rec:?}");
    assert!(rec.total_bytes() >= 3 * 12, "rec = {rec:?}");
    // Canonical endpoints: 10.0.0.1:54321 (a) ↔ 10.0.0.2:80 (b).
    assert!(
        rec.a.port() == 80 || rec.b.port() == 80,
        "expected port 80 endpoint, rec = {rec:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_without_pcap_source_returns_error() {
    // Build with an interface (so NoInterface doesn't fire) but
    // no pcap_source; calling replay should surface the new
    // PcapSourceRequired variant.
    let monitor = Monitor::builder()
        .interface("lo")
        .protocol::<Udp>()
        .build()
        .expect("build");
    match monitor.replay().await {
        Err(Error::Build(BuildError::PcapSourceRequired)) => {}
        other => panic!("expected PcapSourceRequired, got: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn replay_with_pcap_speed_factor_setter() {
    let pcap = write_synthetic_pcap();
    let counter = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&counter);

    // 0.21 E.1: builder-side `pcap_speed_factor(2.0)` should land
    // in the `AsyncPcapConfig::replay_speed` consumed by replay().
    // Smoke-test: at 2× speed the 3-packet pcap replays quickly
    // and at least one FlowStarted fires.
    Monitor::builder()
        .pcap_source(pcap.path())
        .pcap_speed_factor(2.0)
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>| {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_speed_factor")
        .replay()
        .await
        .expect("replay completes");

    assert!(counter.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_isolates_handler_errors() {
    // 0.24 Phase B: a handler that always errors must NOT tear down the run
    // loop under `HandlerErrorPolicy::Isolate` — replay runs to completion and
    // the handler is still invoked.
    let pcap = write_synthetic_pcap();
    let calls = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&calls);

    Monitor::builder()
        .pcap_source(pcap.path())
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>| {
            c.fetch_add(1, Ordering::Relaxed);
            Err(Error::Config("boom".into()))
        })
        .build()
        .expect("build")
        .replay()
        .await
        .expect("replay completes despite handler errors under Isolate");

    assert!(
        calls.load(Ordering::Relaxed) >= 1,
        "the erroring handler should still have been invoked"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_isolated_handler_errors_surface_on_health_counter() {
    // 0.24 Phase B/C: errors swallowed by Isolate are silent by design, so
    // MonitorHealth::handler_errors() makes the silent-drop rate observable.
    let pcap = write_synthetic_pcap();

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(|_e: &FlowStarted<Udp>| Err(Error::Config("boom".into())))
        .build()
        .expect("build");

    // Grab the health handle BEFORE replay consumes the monitor.
    let health = monitor.health();
    assert_eq!(health.handler_errors(), 0, "no errors before replay");

    monitor
        .replay()
        .await
        .expect("replay completes under Isolate");

    assert!(
        health.handler_errors() >= 1,
        "isolated handler errors should be counted on the health handle (got {})",
        health.handler_errors()
    );
    assert_eq!(
        health.backend_errors(),
        0,
        "no backend errors in pcap replay"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_propagates_handler_errors_by_default() {
    // Default policy is Propagate: a handler error tears the monitor down.
    let pcap = write_synthetic_pcap();
    let result = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>| Err(Error::Config("boom".into())))
        .build()
        .expect("build")
        .replay()
        .await;
    assert!(
        result.is_err(),
        "default Propagate policy should surface the handler error"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_on_effect_emits_anomaly_through_the_sink() {
    // 0.25 B1: an async effect handler reads `&Ctx` synchronously, awaits
    // (simulated I/O), and returns `Effects::emit(..)`; the run loop applies
    // the effect to the monitor's sink AFTER the sync/async passes. This
    // exercises the full wiring: on_effect → register_effect → dispatcher
    // effect_slots → run-loop dispatch_lifecycle_effects → Effects::apply.
    use std::borrow::Cow;
    use std::sync::Mutex;

    use netring::anomaly::sink::AnomalySink;
    use netring::anomaly::{OwnedAnomaly, Severity};
    use netring::ctx::Ctx;
    use netring::monitor::Effects;

    // A sink that records the `kind` slug of each anomaly written.
    #[derive(Clone, Default)]
    struct Recording(Arc<Mutex<Vec<&'static str>>>);
    impl AnomalySink for Recording {
        fn write(
            &mut self,
            kind: &'static str,
            _severity: Severity,
            _ts: flowscope::Timestamp,
            _key: Option<&dyn netring::anomaly::key::Key>,
            _observations: &[(&'static str, Cow<'_, str>)],
            _metrics: &[(&'static str, f64)],
        ) {
            self.0.lock().unwrap().push(kind);
        }
    }

    let pcap = write_synthetic_pcap();
    let recorder = Recording::default();
    let kinds = Arc::clone(&recorder.0);

    Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        .sink(recorder)
        .on_effect::<FlowStarted<Udp>>(|_evt: &FlowStarted<Udp>, ctx: &Ctx<'_>| {
            // Synchronous read; move owned data into the 'static future.
            let key = ctx.flow;
            let ts = ctx.ts;
            async move {
                tokio::task::yield_now().await; // simulate async I/O
                let mut a = OwnedAnomaly::new("effect_fired", Severity::Warning.into(), ts);
                if let Some(k) = key {
                    a = a.with_key(&k);
                }
                Ok(Effects::emit(a))
            }
        })
        .build()
        .expect("build with on_effect")
        .replay()
        .await
        .expect("replay completes");

    let recorded = kinds.lock().unwrap();
    // The 3 UDP packets share one flow → one FlowStarted<Udp> → the effect
    // handler fires once and emits exactly one "effect_fired" anomaly.
    assert_eq!(
        recorded.as_slice(),
        &["effect_fired"],
        "expected the effect handler's anomaly to reach the sink, got {recorded:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_packet_tier_subscription_sees_every_matching_frame() {
    // 0.25 A1: the packet tier sees EVERY captured frame (pre-flow), unlike
    // the flow tier which collapses a flow's packets into one FlowStarted.
    // The 3 UDP/80 frames each hit the packet handler → count == 3.
    use netring::monitor::subscription::packet;

    let pcap = write_synthetic_pcap();
    let hits = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&hits);
    let mismatches = Arc::new(AtomicU32::new(0));
    let m = Arc::clone(&mismatches);

    Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        // Matches: udp AND dst_port 80 — every one of the 3 frames.
        .subscribe(packet().udp().dst_port(80).to(move |view, _ctx| {
            assert!(!view.frame.is_empty(), "handler sees the borrowed frame");
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }))
        // Never matches (tcp): proves the filter actually gates.
        .subscribe(packet().tcp().to(move |_view, _ctx| {
            m.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }))
        .build()
        .expect("build with packet subscription")
        .replay()
        .await
        .expect("replay completes");

    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "packet tier should fire once per matching frame (3 UDP/80 packets)"
    );
    assert_eq!(
        mismatches.load(Ordering::Relaxed),
        0,
        "the tcp-filtered sub must not fire on udp frames"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_flow_tier_delivers_once_at_flow_end_gated_by_stats() {
    // 0.25 S3: a flow subscription fires once per flow, at FlowEnded, with the
    // accumulated stats — and the byte/packet filter gates on those stats.
    use std::sync::Mutex;

    use netring::monitor::subscription::flow;
    use netring::protocol::event_typed::FlowEnded;

    let pcap = write_synthetic_pcap(); // 3 UDP packets, one flow
    let ended: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new())); // packet counts seen
    let seen = Arc::clone(&ended);
    let big_fired = Arc::new(AtomicU32::new(0));
    let big = Arc::clone(&big_fired);

    Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        // Matches every UDP flow → fires once with the flow's 3-packet stats.
        .subscribe(flow::<Udp>().to(move |e: &FlowEnded<Udp>, _ctx| {
            seen.lock().unwrap().push(e.stats.total_packets());
            Ok(())
        }))
        // packets_over(10) → the 3-packet flow must NOT fire.
        .subscribe(
            flow::<Udp>()
                .packets_over(10)
                .to(move |_e: &FlowEnded<Udp>, _ctx| {
                    big.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }),
        )
        .build()
        .expect("build with flow subscriptions")
        .replay()
        .await
        .expect("replay completes");

    let counts = ended.lock().unwrap();
    assert_eq!(
        counts.as_slice(),
        &[3],
        "flow tier should deliver exactly once, with the 3-packet stats"
    );
    assert_eq!(
        big_fired.load(Ordering::Relaxed),
        0,
        "packets_over(10) must not fire on a 3-packet flow"
    );
}

/// A UDP/53 frame carrying a minimal DNS A-query for `qname`.
#[cfg(all(feature = "dns", feature = "tls"))]
fn dns_query_frame(qname: &str) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&0x1234u16.to_be_bytes()); // txid
    dns.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD
    dns.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    dns.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar count
    for label in qname.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0); // root label
    dns.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    dns.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

    let total_len = 14 + 20 + 8 + dns.len();
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&((20 + 8 + dns.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.push(64);
    frame.push(17); // UDP
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[10, 0, 0, 1]);
    frame.extend_from_slice(&[10, 0, 0, 2]);
    frame.extend_from_slice(&54321u16.to_be_bytes());
    frame.extend_from_slice(&53u16.to_be_bytes()); // dst port 53
    frame.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&dns);
    frame
}

#[cfg(all(feature = "dns", feature = "tls"))]
#[tokio::test(flavor = "current_thread")]
async fn replay_session_tier_dns_qname_glob_gates_delivery() {
    // 0.25 S3b: a session subscription delivers the parsed DNS message, gated
    // by the qname glob. Two queries (evil.test, good.example); only the one
    // matching `*.test` reaches the handler.
    use std::sync::Mutex;

    use netring::monitor::subscription::session;
    use netring::protocol::builtin::Dns;
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: u32::MAX,
        datalink: pcap_file::DataLink::from(1),
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        endianness: pcap_file::Endianness::native(),
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (i, q) in ["evil.test", "good.example"].iter().enumerate() {
        let frame = dns_query_frame(q);
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).unwrap();
    }
    drop(w);

    let matched: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&matched);

    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Dns>()
        .subscribe(session::<Dns>().qname_glob("*.test").to(
            move |msg: &flowscope::dns::DnsMessage, _ctx| {
                if let flowscope::dns::DnsMessage::Query(q) = msg
                    && let Some(question) = q.questions.first()
                {
                    seen.lock().unwrap().push(question.name.clone());
                }
                Ok(())
            },
        ))
        .build()
        .expect("build with dns session sub")
        .replay()
        .await
        .expect("replay completes");

    let names = matched.lock().unwrap();
    assert_eq!(
        names.as_slice(),
        &["evil.test".to_string()],
        "only the *.test query should reach the gated handler, got {names:?}"
    );
}

#[test]
fn builder_pcap_source_relaxes_no_interface_check() {
    let pcap = write_synthetic_pcap();
    let _m = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        .build()
        .expect("build with pcap_source and no interface");
}
