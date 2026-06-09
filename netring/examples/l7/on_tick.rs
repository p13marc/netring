//! `SessionParser::on_tick` / `DatagramParser::on_tick` demo.
//!
//! New in netring 0.14.0 / flowscope 0.4: parsers can override
//! `on_tick(&mut self, now: Timestamp)` to emit time-driven
//! messages — request timeouts, heartbeats, anything that needs a
//! sweep-cadence wakeup attributed to a specific flow.
//!
//! This example wires a tiny [`DatagramParser`] that tracks the
//! timestamp of the last UDP datagram it saw per side and, on
//! every `on_tick`, emits a `Heartbeat` message if more than 2 s
//! have passed without traffic. The heartbeat carries the
//! observed idle duration — useful for downstream consumers that
//! want to surface "flow alive but quiet" without waiting for the
//! tracker's idle-timeout eviction.
//!
//! Usage:
//!     cargo run -p netring --example async_on_tick \
//!         --features tokio,flow,parse -- [interface] [seconds]

use std::time::Duration;

use flowscope::{DatagramParser, FlowSide, SessionEvent, Timestamp};
use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::extract::FiveTuple;

const HEARTBEAT_AFTER: Duration = Duration::from_secs(2);

#[derive(Default, Clone, Debug)]
struct HeartbeatParser {
    last_seen: Option<Timestamp>,
}

#[derive(Debug)]
enum HeartbeatMsg {
    Datagram { side: FlowSide, len: usize },
    Heartbeat { idle: Duration },
}

impl DatagramParser for HeartbeatParser {
    type Message = HeartbeatMsg;

    fn parse(
        &mut self,
        payload: &[u8],
        side: FlowSide,
        ts: Timestamp,
        out: &mut Vec<Self::Message>,
    ) {
        self.last_seen = Some(ts);
        out.push(HeartbeatMsg::Datagram {
            side,
            len: payload.len(),
        });
    }

    fn on_tick(&mut self, now: Timestamp, out: &mut Vec<Self::Message>) {
        let Some(last) = self.last_seen else {
            return;
        };
        let idle = now.saturating_sub(last);
        if idle >= HEARTBEAT_AFTER {
            // Push the "last seen" anchor forward so we don't fire
            // every single tick — once per HEARTBEAT_AFTER window.
            self.last_seen = Some(now);
            out.push(HeartbeatMsg::Heartbeat { idle });
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!(
        "UDP flow tracking on {iface} for {seconds}s; heartbeat after {HEARTBEAT_AFTER:?} idle"
    );

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap
        .flow_stream(FiveTuple::bidirectional())
        .datagram_stream(HeartbeatParser::default());

    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        match evt? {
            SessionEvent::Started { key, .. } => {
                println!("+ {a} <-> {b}", a = key.a, b = key.b);
            }
            SessionEvent::Application {
                key, message, ts, ..
            } => match message {
                HeartbeatMsg::Datagram { side, len } => {
                    println!(
                        "  [{ts:?}] {side:?} {len} bytes on {a} <-> {b}",
                        a = key.a,
                        b = key.b
                    );
                }
                HeartbeatMsg::Heartbeat { idle } => {
                    println!(
                        "  [{ts:?}] HEARTBEAT (idle {idle:?}) on {a} <-> {b}",
                        a = key.a,
                        b = key.b
                    );
                }
            },
            SessionEvent::Closed { key, reason, .. } => {
                println!("- {a} <-> {b} ({reason:?})", a = key.a, b = key.b);
            }
            _ => {}
        }
    }
    Ok(())
}
