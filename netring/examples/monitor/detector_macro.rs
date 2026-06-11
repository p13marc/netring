//! Demonstrates the `detector!` macro.
//!
//! Three detectors composed in one Monitor:
//!
//! 1. **SshAttempt** — fires on `FlowStarted<Tcp>` to port 22.
//! 2. **HttpRequest** — fires on every HTTP request, counts per
//!    `(method, path)` slug.
//! 3. **DnsQuery** — fires on each DNS Query message.
//!
//! Each detector is a few lines of `detector! { ... }`. The full
//! sink chain prints one JSON line per emission (when built with
//! the `serde` feature) or one text line otherwise.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_detector_macro \
//!     --features "tokio,flow,http,dns" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("monitor_detector_macro: capturing on {iface} for {dur_secs}s");

    // 0.21 A.12: every emit uses `ctx.emit(kind, severity)` —
    // the A.2 shortcut that wraps `let now = ctx.ts;
    // ctx.sink_mut().begin(kind, severity, now)` into one call.
    let ssh_attempt = netring::detector! {
        name:     "SshAttempt",
        severity: Info,
        event:    FlowStarted<Tcp>,
        matches:  |evt| evt.key.either_port(22),
        emit:     |evt, ctx| {
            ctx.emit("SshAttempt", Severity::Info)
                .with_key(&evt.key)
                .emit();
        },
    };

    let http_request = netring::detector! {
        name:     "HttpRequest",
        severity: Info,
        event:    Http,
        matches:  |msg| matches!(msg, flowscope::http::HttpMessage::Request(_)),
        emit:     |msg, ctx| {
            let flowscope::http::HttpMessage::Request(req) = msg else { return };
            let method = std::str::from_utf8(&req.method).unwrap_or("?");
            let path = std::str::from_utf8(&req.path).unwrap_or("?");
            ctx.emit("HttpRequest", Severity::Info)
                .with("method", method.to_string())
                .with("path", path.to_string())
                .emit();
        },
    };

    let dns_query = netring::detector! {
        name:     "DnsQuery",
        severity: Info,
        event:    Dns,
        matches:  |msg| matches!(msg, flowscope::dns::DnsMessage::Query(_)),
        emit:     |msg, ctx| {
            let flowscope::dns::DnsMessage::Query(q) = msg else { return };
            let mut writer = ctx.emit("DnsQuery", Severity::Info);
            if let Some(question) = q.questions.first() {
                writer = writer.with("qname", question.name.to_string());
            }
            writer.emit();
        },
    };

    Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .protocol::<Http>()
        .protocol::<Dns>()
        .detect(ssh_attempt)
        .detect(http_request)
        .detect(dns_query)
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    Ok(())
}
