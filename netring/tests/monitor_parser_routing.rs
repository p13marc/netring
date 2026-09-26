//! Parser events reach the parser's own protocol (#164), anomalies
//! and message sides reach handlers (#165).

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "http"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{AnomalyKind, EndReason, FlowSide, MemcapPolicy};
use netring::ctx::Ctx;
use netring::monitor::Monitor;
use netring::protocol::builtin::{Http, Tcp};
use netring::protocol::event_typed::{AnyFlowAnomaly, ParserClosed, ParserSideStopped};
use tempfile::NamedTempFile;

const REQ: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n";
const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

fn pcap(frames: Vec<Vec<u8>>) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (i, f) in frames.iter().enumerate() {
        w.write_packet(&PcapPacket::new_owned(
            Duration::from_millis(1_000 + i as u64),
            f.len() as u32,
            f.clone(),
        ))
        .unwrap();
    }
    file
}

/// Handshake, the request (optionally in two reversed segments, or
/// with its first 10 bytes lost), the response, FIN exchange.
fn http_flow(reverse_request: bool, lose_head: bool) -> Vec<Vec<u8>> {
    let (c, s, m) = ([10, 0, 0, 1], [10, 0, 0, 2], [0u8; 6]);
    let (ci, si) = (100u32, 900u32);
    let mut v = vec![
        ipv4_tcp(m, m, c, s, 40000, 80, ci, 0, 0x02, &[]),
        ipv4_tcp(m, m, s, c, 80, 40000, si, ci + 1, 0x12, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x10, &[]),
    ];
    let (head, tail) = REQ.split_at(10);
    let head_frame = ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x18, head);
    let tail_frame = ipv4_tcp(m, m, c, s, 40000, 80, ci + 11, si + 1, 0x18, tail);
    if lose_head {
        v.push(tail_frame);
    } else if reverse_request {
        v.push(tail_frame);
        v.push(head_frame);
    } else {
        v.push(ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x18, REQ));
    }
    let cend = ci + 1 + REQ.len() as u32;
    v.push(ipv4_tcp(m, m, s, c, 80, 40000, si + 1, cend, 0x18, RESP));
    let send = si + 1 + RESP.len() as u32;
    v.push(ipv4_tcp(m, m, c, s, 40000, 80, cend, send, 0x11, &[]));
    v.push(ipv4_tcp(m, m, s, c, 80, 40000, send, cend + 1, 0x11, &[]));
    v.push(ipv4_tcp(
        m,
        m,
        c,
        s,
        40000,
        80,
        cend + 1,
        send + 1,
        0x10,
        &[],
    ));
    v
}

/// `ParserClosed<Http>` fires for the HTTP parser (it never did: the
/// event was routed by transport only); `ParserClosed<Tcp>` still
/// fires for every TCP parser.
#[tokio::test(flavor = "current_thread")]
async fn parser_closed_reaches_the_parsers_protocol_and_its_transport() {
    let file = pcap(http_flow(false, false));
    let http = Arc::new(Mutex::new(Vec::new()));
    let tcp = Arc::new(Mutex::new(0usize));
    let (h, t) = (Arc::clone(&http), Arc::clone(&tcp));
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .protocol::<Http>()
        .on::<ParserClosed<Http>>(move |e: &ParserClosed<Http>| {
            h.lock().unwrap().push((e.parser_kind, e.reason));
            Ok(())
        })
        .on::<ParserClosed<Tcp>>(move |_e: &ParserClosed<Tcp>| {
            *t.lock().unwrap() += 1;
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(
        *http.lock().unwrap(),
        vec![(flowscope::ParserKind::Http1, EndReason::Fin)]
    );
    assert_eq!(*tcp.lock().unwrap(), 1);
}

/// A memcap that releases one side stops the HTTP parser's reading of
/// that side: `ParserSideStopped<Http>` and `<Tcp>` both fire.
#[tokio::test(flavor = "current_thread")]
async fn parser_side_stops_are_routed_too() {
    let file = pcap(http_flow(true, false));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let tcp = Arc::new(Mutex::new(0usize));
    let (s, t) = (Arc::clone(&seen), Arc::clone(&tcp));
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .protocol::<Http>()
        .reassembly_memcap(16, MemcapPolicy::PassThrough)
        .on::<ParserSideStopped<Http>>(move |e: &ParserSideStopped<Http>| {
            s.lock().unwrap().push((e.side, e.reason));
            Ok(())
        })
        .on::<ParserSideStopped<Tcp>>(move |_e: &ParserSideStopped<Tcp>| {
            *t.lock().unwrap() += 1;
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(FlowSide::Initiator, EndReason::BufferOverflow)]
    );
    assert_eq!(*tcp.lock().unwrap(), 1);
}

/// Registering an `AnyFlowAnomaly` handler turns anomalies on.
#[tokio::test(flavor = "current_thread")]
async fn an_anomaly_handler_enables_anomalies() {
    let file = pcap(http_flow(false, true));
    let kinds = Arc::new(Mutex::new(Vec::new()));
    let k = Arc::clone(&kinds);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .protocol::<Http>()
        .on::<AnyFlowAnomaly>(move |a: &AnyFlowAnomaly| {
            k.lock().unwrap().push(a.kind.clone());
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let kinds = kinds.lock().unwrap();
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, AnomalyKind::StreamGap { bytes: 10, .. })),
        "{kinds:?}"
    );
}

/// L7 handlers see which peer sent the message.
#[tokio::test(flavor = "current_thread")]
async fn message_handlers_see_the_side() {
    let file = pcap(http_flow(false, false));
    let sides = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&sides);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .protocol::<Http>()
        .on_ctx::<Http>(
            move |msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>| {
                let kind = matches!(msg, flowscope::http::HttpMessage::Request(_));
                s.lock().unwrap().push((kind, ctx.side()));
                Ok(())
            },
        )
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(
        *sides.lock().unwrap(),
        vec![
            (true, Some(FlowSide::Initiator)),
            (false, Some(FlowSide::Responder))
        ]
    );
}
