//! Offline pcap → typed `SessionEvent` stream in one expression.
//!
//! Demonstrates [`AsyncPcapSource::sessions`] (new in netring
//! 0.14.0 / flowscope 0.4). The hand-rolled parser below counts
//! request/response byte volumes per side; the stream yields
//! lifecycle `Started` / `Closed` events plus one `Application`
//! event per packet drained from the reassembler.
//!
//! The end-of-input flush (`finish()` at `Timestamp::MAX`) is
//! folded in — every still-open flow at EOF emits a terminal
//! `SessionEvent::Closed`.
//!
//! Usage:
//!     cargo run -p netring --example async_pcap_sessions \
//!         --features tokio,flow,parse,pcap -- trace.pcap [speed]

use std::env;

use flowscope::{FlowSide, SessionEvent, SessionParser, Timestamp};
use futures::StreamExt;
use netring::AsyncPcapSource;
use netring::flow::extract::FiveTuple;

/// Minimal `SessionParser` that emits a `(side, byte_count)` tuple
/// every time it sees bytes. Real parsers do framing here.
#[derive(Default, Clone, Debug)]
struct ByteCounter;

#[derive(Debug)]
struct Counted {
    side: FlowSide,
    bytes: usize,
    ts: Timestamp,
}

impl SessionParser for ByteCounter {
    type Message = Counted;

    fn feed_initiator(&mut self, b: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>) {
        out.push(Counted {
            side: FlowSide::Initiator,
            bytes: b.len(),
            ts,
        });
    }

    fn feed_responder(&mut self, b: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>) {
        out.push(Counted {
            side: FlowSide::Responder,
            bytes: b.len(),
            ts,
        });
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: async_pcap_sessions <pcap> [speed]")?;

    eprintln!("[sessions] {path}");

    let source = AsyncPcapSource::open(&path).await?;
    let mut sessions = source.sessions(FiveTuple::bidirectional(), ByteCounter);

    let mut total_init = 0u64;
    let mut total_resp = 0u64;
    let mut messages = 0u64;
    let mut closed = 0u64;

    while let Some(evt) = sessions.next().await {
        match evt? {
            SessionEvent::Started { key, .. } => {
                println!("+ {a} <-> {b}", a = key.a, b = key.b);
            }
            SessionEvent::Application { message, .. } => {
                messages += 1;
                match message.side {
                    FlowSide::Initiator => total_init += message.bytes as u64,
                    FlowSide::Responder => total_resp += message.bytes as u64,
                }
                let _ = message.ts; // available for time-driven correlation
            }
            SessionEvent::Closed { key, reason, .. } => {
                closed += 1;
                println!("- {a} <-> {b} ({reason:?})", a = key.a, b = key.b);
            }
            SessionEvent::FlowAnomaly { kind, .. } => {
                eprintln!("! flow anomaly: {kind:?}");
            }
            SessionEvent::TrackerAnomaly { kind, .. } => {
                eprintln!("! tracker anomaly: {kind:?}");
            }
            _ => {}
        }
    }

    eprintln!(
        "[done] {closed} flows closed, {messages} messages \
         (init={total_init} bytes, resp={total_resp} bytes), \
         packets_read={}",
        sessions.packets_read()
    );
    Ok(())
}
