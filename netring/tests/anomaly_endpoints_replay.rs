//! #215: an anomaly a handler raises about the current flow reaches the
//! sinks read from the flow's **initiator** — `src` is the endpoint that
//! opened the connection, not the lower address the flow key sorts first.
//!
//! The flows here are opened by 10.0.0.2:40000 towards 10.0.0.1:80, so the
//! address-sorted key puts the server first (`a` = 10.0.0.1:80): before
//! 0.32 every sink reported the server as the source. No capture
//! privileges.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

mod helpers;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use helpers::pcap::{flow_between, write_pcap};
use netring::anomaly::Severity;
use netring::anomaly::shipped_sinks::ChannelSink;
use netring::ctx::Ctx;
use netring::monitor::{Monitor, MonitorBuilder};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowEnded;

const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40_000);
const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80);

/// A pcap of one TCP connection CLIENT → SERVER carrying `segments`.
fn client_to_server_pcap(dir: &Path, segments: &[(u32, Vec<u8>)]) -> std::path::PathBuf {
    let frames = flow_between([10, 0, 0, 2], [10, 0, 0, 1], 40_000, 80, segments);
    write_pcap(dir, "client_to_server", &frames)
}

/// Replay `pcap` through `builder` (sink = a ChannelSink) and return what
/// the channel received.
async fn replay_into_channel(
    pcap: &Path,
    builder: impl FnOnce(MonitorBuilder) -> MonitorBuilder,
) -> Vec<netring::anomaly::OwnedAnomaly> {
    let (sink, mut rx) = ChannelSink::channel();
    builder(
        Monitor::builder()
            .pcap_source(pcap)
            .protocol::<Tcp>()
            .sink(sink),
    )
    .build()
    .unwrap()
    .replay()
    .await
    .unwrap();
    let mut got = Vec::new();
    while let Ok(a) = rx.try_recv() {
        got.push(a);
    }
    got
}

fn src_dest(a: &netring::anomaly::OwnedAnomaly) -> (Option<SocketAddr>, Option<SocketAddr>) {
    let sock = |ip: Option<IpAddr>, port: Option<u16>| Some(SocketAddr::new(ip?, port?));
    (sock(a.src_ip, a.src_port), sock(a.dest_ip, a.dest_port))
}

/// A `FlowEnded` handler keys its anomaly with the event's (address-sorted)
/// flow key: the sink still sees CLIENT as the source.
#[tokio::test(flavor = "current_thread")]
async fn flow_anomaly_is_read_from_the_initiator() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = client_to_server_pcap(dir.path(), &[(0, b"hello".to_vec())]);
    let got = replay_into_channel(&pcap, |b| {
        b.on_ctx::<FlowEnded<Tcp>>(|e: &FlowEnded<Tcp>, ctx: &mut Ctx<'_>| {
            // The key sorts the server first; the sinks must not.
            assert_eq!((e.key.a, e.key.b), (SERVER, CLIENT));
            ctx.emit("FlowDone", Severity::Info).with_key(&e.key).emit();
            Ok(())
        })
    })
    .await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(src_dest(&got[0]), (Some(CLIENT), Some(SERVER)));
    assert_eq!(got[0].proto, Some("TCP"));
}

/// An L7 handler keying its anomaly with `ctx.flow`: the initiator comes
/// from the message's side (the request is the client's).
#[cfg(feature = "http")]
#[tokio::test(flavor = "current_thread")]
async fn l7_anomaly_is_read_from_the_initiator() {
    use netring::protocol::builtin::Http;
    let dir = tempfile::tempdir().unwrap();
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let pcap = client_to_server_pcap(dir.path(), &[(0, req)]);
    let got = replay_into_channel(&pcap, |b| {
        b.protocol::<Http>().on_ctx::<Http>(
            |_m: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>| {
                let key = ctx.flow.expect("an L7 message has a flow");
                ctx.emit("HttpSeen", Severity::Info).with_key(&key).emit();
                Ok(())
            },
        )
    })
    .await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(src_dest(&got[0]), (Some(CLIENT), Some(SERVER)));
}

/// A key that is not the current flow keeps the order it was built in
/// (there is no initiator to read it from).
#[tokio::test(flavor = "current_thread")]
async fn a_foreign_key_keeps_its_stored_order() {
    let other = flowscope::extract::FiveTupleKey::new(
        flowscope::L4Proto::Udp,
        "192.0.2.9:7".parse().unwrap(),
        "192.0.2.1:9".parse().unwrap(),
    );
    let dir = tempfile::tempdir().unwrap();
    let pcap = client_to_server_pcap(dir.path(), &[]);
    let got = replay_into_channel(&pcap, move |b| {
        b.on_ctx::<FlowEnded<Tcp>>(move |_e: &FlowEnded<Tcp>, ctx: &mut Ctx<'_>| {
            ctx.emit("Other", Severity::Info).with_key(&other).emit();
            Ok(())
        })
    })
    .await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(src_dest(&got[0]), (Some(other.a), Some(other.b)));
}

/// The OCSF sink's `src_endpoint` is the initiator too (it read the key's
/// `a` before 0.32).
#[cfg(feature = "ocsf-sink")]
#[tokio::test(flavor = "current_thread")]
async fn ocsf_src_endpoint_is_the_initiator() {
    use std::sync::{Arc, Mutex};

    use netring::anomaly::ocsf_sink::OcsfSink;

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

    let buf = SharedBuf::default();
    let dir = tempfile::tempdir().unwrap();
    let pcap = client_to_server_pcap(dir.path(), &[]);
    Monitor::builder()
        .pcap_source(&pcap)
        .protocol::<Tcp>()
        .sink(OcsfSink::new(buf.clone()))
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
    assert_eq!(v["src_endpoint"]["ip"], "10.0.0.2", "{v}");
    assert_eq!(v["src_endpoint"]["port"], 40_000);
    assert_eq!(v["dst_endpoint"]["ip"], "10.0.0.1");
    assert_eq!(v["dst_endpoint"]["port"], 80);
}

/// So is the EVE sink's `src_ip` / `src_port`.
#[cfg(feature = "eve-sink")]
#[tokio::test(flavor = "current_thread")]
async fn eve_src_is_the_initiator() {
    use std::sync::{Arc, Mutex};

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

    let buf = SharedBuf::default();
    let dir = tempfile::tempdir().unwrap();
    let pcap = client_to_server_pcap(dir.path(), &[]);
    Monitor::builder()
        .pcap_source(&pcap)
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
    assert_eq!(v["dest_port"], 80);
}
