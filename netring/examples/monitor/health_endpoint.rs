//! Health endpoint (0.24 Phase C4): expose a monitor's readiness +
//! liveness over HTTP, the way a Kubernetes `/readyz` / `/healthz` probe
//! consumes them — with **no web-framework dependency**, just a tiny
//! hand-rolled tokio HTTP/1.1 responder.
//!
//! `monitor.health()` hands out a cheap, cloneable [`MonitorHealth`]
//! handle (a few atomics). Grab it *before* spawning the run loop, clone
//! it into the HTTP task, and the run loop updates it as it captures.
//!
//! - `GET /readyz`  → 200 once the capture sockets are open (else 503).
//! - `GET /healthz` → 200 while the loop is making progress within the
//!   liveness window (else 503). On a quiet link, register a heartbeat
//!   `.tick(..)` so liveness has a signal — see the note below.
//! - `GET /` (anything else) → a one-line JSON-ish health snapshot.
//!
//! ```sh
//! cargo run --example monitor_health_endpoint \
//!     --features "monitor-quickstart" -- eth0 8088
//! # then: curl -s localhost:8088/readyz ; curl -s localhost:8088/
//! ```
//!
//! [`MonitorHealth`]: netring::monitor::MonitorHealth

use std::time::Duration;

use netring::monitor::{Monitor, MonitorHealth};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::Tick;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Heartbeat tick: a no-op that just counts as "progress" so liveness
/// stays green on a quiet link. A named `fn` (rather than an inline
/// closure) sidesteps the higher-ranked-lifetime inference the bare
/// `|_ctx| Ok(())` form trips on.
fn heartbeat(_tick: &Tick) -> Result<(), netring::Error> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let port: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8088);

    // The liveness window: how long without an event before /healthz
    // reports unhealthy. A heartbeat tick (below) guarantees an event
    // every second, so even a silent link stays live.
    let liveness_window = Duration::from_secs(5);

    let monitor = Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        // Heartbeat: a 1s tick is "progress" for liveness, so a quiet
        // link doesn't read as dead. (Readiness needs no traffic at all.)
        .tick(Duration::from_secs(1), heartbeat)
        .build()?;

    // Grab the health handle BEFORE moving the monitor into the run loop.
    let health = monitor.health();

    eprintln!(
        "monitor_health_endpoint: capturing {iface}; health on http://127.0.0.1:{port}/ \
         (try /readyz, /healthz)"
    );

    // Serve health over a tiny HTTP/1.1 responder.
    let http = tokio::spawn(serve_health(health, port, liveness_window));

    // Run the monitor for a while (Ctrl-C also works via run_until_signal).
    monitor.run_for(Duration::from_secs(120)).await?;

    http.abort();
    Ok(())
}

/// Minimal, dependency-free HTTP/1.1 health responder. Reads the request
/// line, routes on the path, writes a fixed response, closes. Not a real
/// web server — just enough to answer a probe.
async fn serve_health(health: MonitorHealth, port: u16, liveness_window: Duration) {
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("health endpoint: cannot bind port {port}: {e}");
            return;
        }
    };

    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let mut buf = [0u8; 1024];
        let n = match sock.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req
            .split_whitespace()
            .nth(1) // "GET <path> HTTP/1.1"
            .unwrap_or("/");

        let (status, body) = match path {
            "/readyz" => readiness(&health),
            "/healthz" => liveness(&health, liveness_window),
            _ => (200, snapshot_line(&health)),
        };

        let response = format!(
            "HTTP/1.1 {status} {reason}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\r\n{body}",
            reason = if status == 200 { "OK" } else { "Service Unavailable" },
            len = body.len(),
        );
        let _ = sock.write_all(response.as_bytes()).await;
        let _ = sock.shutdown().await;
    }
}

fn readiness(health: &MonitorHealth) -> (u16, String) {
    let ready = health.is_ready();
    let status = if ready { 200 } else { 503 };
    (status, format!("{{\"ready\":{ready}}}"))
}

fn liveness(health: &MonitorHealth, window: Duration) -> (u16, String) {
    let live = health.is_live(window);
    let status = if live { 200 } else { 503 };
    (status, format!("{{\"live\":{live}}}"))
}

fn snapshot_line(health: &MonitorHealth) -> String {
    let s = health.snapshot();
    format!(
        "{{\"ready\":{},\"seen_traffic\":{},\"uptime_s\":{},\"active_flows\":{},\
         \"last_event_age_ms\":{},\"packets\":{},\"drops\":{}}}",
        s.ready,
        s.seen_traffic,
        s.uptime.as_secs(),
        s.active_flows,
        s.last_event_age
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|| "null".into()),
        s.packets,
        s.drops,
    )
}
