//! The Monitor's reassembly settings reach its L7 parsers.
//!
//! netring 0.30 registered protocol slots on flowscope's driver builder
//! *before* `build()` applied `tracker_config`, and flowscope 0.24 slots
//! snapshotted their config at registration — so `reassembly_memcap`
//! (and every other tracker setting) never reached the parsers. With
//! flowscope 0.25 the driver has one engine and the config applies to it
//! whatever the order.

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
use flowscope::{EndReason, MemcapPolicy};
use netring::monitor::Monitor;
use netring::protocol::builtin::{Http, Tcp};
use netring::protocol::event_typed::ParserClosed;
use tempfile::NamedTempFile;

fn http_pcap() -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let (c, s, m) = ([10, 0, 0, 1], [10, 0, 0, 2], [0u8; 6]);
    let req = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n";
    let frames = [
        ipv4_tcp(m, m, c, s, 40000, 80, 100, 0, 0x02, &[]),
        ipv4_tcp(m, m, s, c, 80, 40000, 900, 101, 0x12, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, 101, 901, 0x10, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, 101, 901, 0x18, req),
    ];
    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: u32::MAX,
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        endianness: pcap_file::Endianness::native(),
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

async fn run(memcap: Option<u64>) -> (usize, Vec<EndReason>) {
    let pcap = http_pcap();
    let messages = Arc::new(Mutex::new(0usize));
    let closes = Arc::new(Mutex::new(Vec::new()));
    let (m, c) = (Arc::clone(&messages), Arc::clone(&closes));
    let mut builder = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Tcp>()
        .protocol::<Http>()
        .on::<Http>(move |_msg: &flowscope::http::HttpMessage| {
            *m.lock().unwrap() += 1;
            Ok(())
        })
        .on::<ParserClosed<Tcp>>(move |e: &ParserClosed<Tcp>| {
            c.lock().unwrap().push(e.reason);
            Ok(())
        });
    if let Some(cap) = memcap {
        // Set *after* the protocol registration on purpose.
        builder = builder.reassembly_memcap(cap, MemcapPolicy::DropFlow);
    }
    builder.build().unwrap().replay().await.unwrap();
    let n = *messages.lock().unwrap();
    let closes = closes.lock().unwrap().clone();
    (n, closes)
}

#[tokio::test(flavor = "current_thread")]
async fn without_a_memcap_the_request_is_parsed() {
    let (messages, _) = run(None).await;
    assert_eq!(messages, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_memcap_set_after_registration_reaches_the_http_parser() {
    let (messages, closes) = run(Some(16)).await;
    assert_eq!(messages, 0, "the request exceeded the memcap");
    assert!(
        closes.contains(&EndReason::BufferOverflow),
        "the HTTP parser was closed by the memcap: {closes:?}"
    );
}
