//! HTTP/1.x request/response observation over a live capture.
//!
//! Real-life pattern: kernel-side BPF filter narrows to TCP/80 +
//! TCP/8080 so the userland flow tracker only sees web traffic.
//! `session_stream(HttpParser::default())` handles TCP reassembly,
//! request/response framing, header parsing — we just consume
//! [`HttpMessage`] events.
//!
//! Output:
//!
//! ```text
//! + flow 10.0.0.5:54321 <-> 10.0.0.10:80
//!   →  GET / HTTP/1.1
//!   ←  200 OK   1284 bytes
//!   →  GET /favicon.ico HTTP/1.1
//!   ←  404 Not Found   123 bytes
//! - flow 10.0.0.5:54321 <-> 10.0.0.10:80  Fin
//! ```
//!
//! Usage:
//!     cargo run -p netring --example http_session \
//!         --features tokio,http -- [interface] [seconds]
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "http"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use flowscope::SessionEvent;
    use flowscope::http::{HttpMessage, HttpParser};
    use futures::StreamExt;
    use netring::flow::extract::FiveTuple;
    use netring::{AsyncCapture, BpfFilter};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    // Kernel-side filter: only TCP traffic to/from common HTTP ports.
    // The flow tracker never sees the rest of the wire — big CPU win.
    let filter = BpfFilter::builder()
        .tcp()
        .dst_port(80)
        .or(|b| b.tcp().src_port(80))
        .or(|b| b.tcp().dst_port(8080))
        .or(|b| b.tcp().src_port(8080))
        .build()?;

    eprintln!(
        "[http] watching {iface} for {seconds}s (TCP/80, TCP/8080)\n\
         BPF filter: {} instructions",
        filter.len()
    );

    let cap = AsyncCapture::open_with_filter(&iface, filter)?;
    let mut stream = cap
        .flow_stream(FiveTuple::bidirectional())
        .session_stream(HttpParser::default());

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut req_count = 0u64;
    let mut resp_count = 0u64;
    let mut flow_count = 0u64;

    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        match evt? {
            SessionEvent::Started { key, .. } => {
                flow_count += 1;
                println!("+ flow {a} <-> {b}", a = key.a, b = key.b);
            }
            SessionEvent::Application { message, .. } => match message {
                HttpMessage::Request(req) => {
                    req_count += 1;
                    println!(
                        "  →  {method} {path} {ver:?}",
                        method = req.method,
                        path = req.path,
                        ver = req.version
                    );
                }
                HttpMessage::Response(resp) => {
                    resp_count += 1;
                    println!(
                        "  ←  {status} {reason}   {len} bytes",
                        status = resp.status,
                        reason = resp.reason,
                        len = resp.body.len()
                    );
                }
            },
            SessionEvent::Closed { key, reason, .. } => {
                println!("- flow {a} <-> {b}  {reason:?}", a = key.a, b = key.b);
            }
            SessionEvent::Anomaly { kind, .. } => {
                eprintln!("! anomaly: {kind:?}");
            }
            _ => {}
        }
    }

    eprintln!("[done] {flow_count} flows seen, {req_count} requests, {resp_count} responses");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "http")))]
fn main() {
    eprintln!("Build with --features tokio,http");
}
