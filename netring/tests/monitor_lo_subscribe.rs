//! Root-gated end-to-end test for `Monitor::subscribe::<Http>()`.
//!
//! Mints a Monitor with `.with_broadcast::<Http>()`, opens a
//! subscriber, runs the monitor against `lo` while a synthetic
//! HTTP request/response pair flies over the loopback, and
//! asserts the EventStream actually receives at least one
//! HttpMessage.
//!
//! Needs `CAP_NET_RAW` on the test binary (`just setcap` or run as
//! root). Gated on the `integration-tests` Cargo feature alongside
//! the rest of the root-only suite.
//!
//! The test uses a `current_thread` runtime so the (currently
//! `!Send`) `Monitor::run_for` future + the broadcast subscriber
//! stream can co-exist on one task via `tokio::select!` — same
//! pattern as `tests/monitor_lo_dispatch.rs`. End-user code that
//! wants `Send` typically pairs the monitor with `ChannelSink`
//! instead of holding a subscriber stream across spawn boundaries.
//!
//! Run with:
//!
//! ```sh
//! just setcap
//! cargo nextest run -p netring \
//!     --features "tokio,channel,flow,parse,http,integration-tests" \
//!     -E 'binary(monitor_lo_subscribe)'
//! ```

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "http",
    feature = "integration-tests"
))]

use std::time::Duration;

use futures::StreamExt;
use netring::error::Error;
use netring::monitor::Monitor;
use netring::protocol::builtin::Http;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "current_thread")]
async fn monitor_lo_subscribe_yields_http_message_from_real_traffic() {
    // Tiny in-process HTTP/1.1 server on lo. Accepts connections
    // in a loop, reads a request, returns a 200 OK, closes. This
    // gives the HTTP parser real request + response bytes to chew
    // on while we hold the broadcast subscriber.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral lo socket");
    let target = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_millis(200), sock.read(&mut buf)).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = sock.shutdown().await;
        }
    });

    // Build the Monitor + open the subscriber before running.
    // `with_broadcast::<Http>()` enrols the broadcast slot;
    // `subscribe::<Http>()` mints an EventStream<HttpMessage>.
    let build_result = Monitor::builder()
        .interface("lo")
        .with_broadcast::<Http>()
        .build();

    let monitor = match build_result {
        Ok(m) => m,
        Err(Error::PermissionDenied) => {
            eprintln!("Skipping: needs CAP_NET_RAW on the test binary (run `just setcap`)");
            server.abort();
            return;
        }
        Err(e) => {
            eprintln!("Skipping: Monitor::build returned {e:?}");
            server.abort();
            return;
        }
    };

    let mut stream = monitor
        .subscribe::<Http>()
        .expect("subscribe to Http broadcast slot");

    // Fire synthetic HTTP requests on a small loop while the
    // monitor runs. The first 150ms gives the AF_PACKET ring time
    // to wire up before any traffic flies.
    let client = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        for _ in 0..4 {
            let Ok(mut sock) = tokio::net::TcpStream::connect(target).await else {
                continue;
            };
            let _ = sock
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await;
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    });

    // Race the monitor's run loop against the broadcast subscriber.
    // `tokio::select!` polls both on the same task, so the !Send
    // run_for future + the stream pull live happily together. The
    // run_for arm caps wall-clock at 3s.
    let result = tokio::select! {
        biased;
        msg = stream.next() => msg,
        _ = monitor.run_for(Duration::from_secs(3)) => None,
    };

    // Cleanup.
    let _ = client.await;
    server.abort();

    match result {
        Some(_msg) => { /* success — one HttpMessage rode the broadcast slot */ }
        None => panic!(
            "no HttpMessage observed within the run_for window — \
             expected the synthetic request to land on the broadcast slot"
        ),
    }
}
