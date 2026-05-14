//! Integration tests for plan 20: `StreamCapture` trait + pcap tap.
//!
//! Requires `CAP_NET_RAW`. Run with:
//!   cargo test --features integration-tests,tokio,flow,parse,pcap

#![cfg(all(
    feature = "integration-tests",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

mod helpers;

use std::io::Cursor;
use std::time::Duration;

use futures::StreamExt;
use netring::flow::extract::FiveTuple;
use netring::pcap::CaptureWriter;
use netring::{AsyncCapture, CaptureBuilder, Dedup, StreamCapture, TapErrorPolicy};

fn build_async_capture() -> AsyncCapture<netring::Capture> {
    let rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");
    AsyncCapture::new(rx).expect("AsyncCapture::new")
}

#[test]
fn capture_stats_on_fresh_flow_stream_is_zero() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let cap = build_async_capture();
        let stream = cap.flow_stream(FiveTuple::bidirectional());
        let stats = stream.capture_stats().expect("capture_stats");
        // Fresh `lo` capture; we haven't polled yet.
        assert_eq!(stats.packets, 0, "no packets on a freshly-built stream");
        assert_eq!(stats.drops, 0);
    });
}

#[test]
fn capture_stats_survives_session_stream_conversion() {
    use flowscope::{SessionParser, SessionParserFactory};

    #[derive(Default, Clone)]
    struct StubParser;
    impl SessionParser for StubParser {
        type Message = ();
        fn feed_initiator(&mut self, _: &[u8]) -> Vec<()> {
            Vec::new()
        }
        fn feed_responder(&mut self, _: &[u8]) -> Vec<()> {
            Vec::new()
        }
    }
    #[derive(Default, Clone)]
    struct StubFactory;
    impl<K> SessionParserFactory<K> for StubFactory {
        type Parser = StubParser;
        fn new_parser(&mut self, _key: &K) -> Self::Parser {
            StubParser
        }
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let cap = build_async_capture();
        let stream = cap
            .flow_stream(FiveTuple::bidirectional())
            .session_stream(StubFactory);
        // Call works on the SessionStream — proves the trait impl
        // is in scope and the accessor reaches through.
        let _stats = stream.capture_stats().expect("capture_stats");
    });
}

#[test]
fn capture_cumulative_stats_is_monotonic() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let cap = build_async_capture();
        let stream = cap.dedup_stream(Dedup::loopback());

        let a = stream
            .capture_cumulative_stats()
            .expect("first cumulative_stats");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let b = stream
            .capture_cumulative_stats()
            .expect("second cumulative_stats");

        assert!(b.packets >= a.packets);
        assert!(b.drops >= a.drops);
    });
}

#[test]
fn pcap_tap_records_what_flow_stream_sees() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let port = helpers::unique_port();
        let marker = format!("netring_tap_{port}");

        // Tap to an in-memory buffer.
        let pcap_buf = Cursor::new(Vec::<u8>::new());
        let writer = CaptureWriter::create(pcap_buf).expect("create CaptureWriter");

        let cap = build_async_capture();
        let mut stream = cap
            .flow_stream(FiveTuple::bidirectional())
            .with_dedup(Dedup::loopback())
            .with_pcap_tap(writer);

        // Send some traffic.
        let marker_clone = marker.clone();
        let sender = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            helpers::send_udp_to_loopback(port, marker_clone.as_bytes(), 3);
        });

        // Drain a few events so the tap runs.
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        let mut evt_count = 0;
        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                evt = stream.next() => match evt {
                    Some(Ok(_)) => {
                        evt_count += 1;
                        if evt_count >= 6 { break; }
                    }
                    Some(Err(e)) => panic!("flow stream error: {e}"),
                    None => break,
                }
            }
        }

        sender.await.unwrap();
        // Sanity: at least one event surfaced (some Started/Packet/Ended for our UDP flow).
        assert!(evt_count > 0, "no flow events drained");

        // Streams hide their tap writer behind the boxed dyn — we can't
        // recover the recorded bytes from here in this simple test.
        // The unit tests in `pcap_tap::tests` cover policy semantics
        // independently; this test asserts that the tap-equipped stream
        // polls without erroring under real traffic.
    });
}

#[test]
fn fail_stream_policy_terminates_on_writer_error() {
    use std::io;

    /// Writer that errors on every `write`. Used to verify that
    /// `TapErrorPolicy::FailStream` actually surfaces an error from
    /// the next `stream.next().await`.
    struct AlwaysFails;
    impl io::Write for AlwaysFails {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("simulated"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let port = helpers::unique_port();
        let marker = format!("netring_failtap_{port}");

        // The first thing CaptureWriter does is write the pcap header,
        // which fails immediately. So we need a writer that buffers the
        // header but fails on packets. Use a Cursor that flips to
        // failing after the header bytes are written.
        struct FailAfterHeader {
            buf: Vec<u8>,
            header_done: bool,
        }
        impl io::Write for FailAfterHeader {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if self.header_done {
                    return Err(io::Error::other("simulated post-header failure"));
                }
                self.buf.extend_from_slice(b);
                // PCAP file header is 24 bytes — flip after that.
                if self.buf.len() >= 24 {
                    self.header_done = true;
                }
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let writer = CaptureWriter::create(FailAfterHeader {
            buf: Vec::new(),
            header_done: false,
        })
        .expect("header write OK");

        let cap = build_async_capture();
        let mut stream = cap
            .flow_stream(FiveTuple::bidirectional())
            .with_dedup(Dedup::loopback())
            .with_pcap_tap_policy(writer, TapErrorPolicy::FailStream);

        // Suppress unused warning if AlwaysFails is reused.
        let _: Option<AlwaysFails> = None;

        // Trigger traffic.
        let marker_clone = marker.clone();
        let _sender = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            helpers::send_udp_to_loopback(port, marker_clone.as_bytes(), 5);
        });

        // Drain until we see an error (FailStream) or timeout.
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        let mut got_error = false;
        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                evt = stream.next() => match evt {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => { got_error = true; break; }
                    None => break,
                }
            }
        }
        assert!(
            got_error,
            "FailStream policy should surface an Err from poll_next"
        );
    });
}
