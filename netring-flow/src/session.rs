//! Pluggable L7 message parsers.
//!
//! Two trait families:
//!
//! - [`SessionParser`] — for **stream-based** protocols (HTTP/1, TLS,
//!   DNS-over-TCP). One parser per session; receives bytes via
//!   `feed_initiator` / `feed_responder`; returns a `Vec` of typed
//!   messages every call. Pair with `netring::SessionStream` to get
//!   an async stream of L7 events.
//!
//! - [`DatagramParser`] — for **packet-based** protocols (DNS-over-UDP,
//!   syslog, NTP, SNMP). Receives one L4 payload at a time. Pair with
//!   `netring::DatagramStream`.
//!
//! Both trait shapes return owned `Vec<Message>` rather than borrowed
//! iterators or `SmallVec` to keep the public API stable across
//! versions of `smallvec` etc. The per-call allocation is amortized
//! across many bytes worth of work.
//!
//! # SessionParser vs `Reassembler`
//!
//! [`crate::Reassembler`] is the lower-level hook: one instance per
//! `(flow, side)`, receives raw TCP segments, callback-driven via
//! a user-supplied handler. `SessionParser` is the higher-level
//! abstraction: one instance per flow, two `feed_*` methods,
//! returns typed messages directly. Pick whichever fits your
//! integration:
//!
//! | Concern                       | `Reassembler`           | `SessionParser`             |
//! |-------------------------------|-------------------------|------------------------------|
//! | Granularity                   | per (flow, side)        | per flow                     |
//! | Output                        | callback (Handler)      | iterator/`Stream` of messages|
//! | Cross-direction state         | painful                 | natural                      |
//! | UDP support                   | no                      | use [`DatagramParser`]       |
//!
//! # Example
//!
//! ```
//! use netring_flow::{FlowSide, SessionParser};
//!
//! #[derive(Default, Clone)]
//! struct LineParser {
//!     init_buf: Vec<u8>,
//!     resp_buf: Vec<u8>,
//! }
//!
//! impl SessionParser for LineParser {
//!     type Message = (FlowSide, String);
//!
//!     fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
//!         feed(&mut self.init_buf, bytes, FlowSide::Initiator)
//!     }
//!     fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
//!         feed(&mut self.resp_buf, bytes, FlowSide::Responder)
//!     }
//! }
//!
//! fn feed(buf: &mut Vec<u8>, bytes: &[u8], side: FlowSide) -> Vec<(FlowSide, String)> {
//!     buf.extend_from_slice(bytes);
//!     let mut out = Vec::new();
//!     while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
//!         let line = String::from_utf8_lossy(&buf[..nl]).into_owned();
//!         out.push((side, line));
//!         buf.drain(..=nl);
//!     }
//!     out
//! }
//! ```

use crate::event::{EndReason, FlowSide, FlowStats};
use crate::timestamp::Timestamp;

/// Parses a stream-oriented L7 protocol session. One instance per
/// flow; both directions feed through the same parser, allowing
/// state to interleave.
///
/// Implementors are owned by the per-flow slot; sync (no `await`).
/// Backpressure flows from the consuming `Stream` back to the
/// kernel ring once the per-flow message buffer fills up — see
/// the `netring::SessionStream` adapter.
pub trait SessionParser: Send + 'static {
    /// L7 message produced by this parser. `Send + 'static` so it
    /// can cross task boundaries when streamed.
    type Message: Send + 'static;

    /// Feed the next chunk of bytes from the **initiator** side.
    /// Returns any complete messages parsed during this call.
    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message>;

    /// Feed the next chunk of bytes from the **responder** side.
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message>;

    /// Initiator side has FIN'd. Default: return nothing.
    fn fin_initiator(&mut self) -> Vec<Self::Message> {
        Vec::new()
    }

    /// Responder side has FIN'd.
    fn fin_responder(&mut self) -> Vec<Self::Message> {
        Vec::new()
    }

    /// Initiator side observed a RST. Default: no-op.
    fn rst_initiator(&mut self) {}

    /// Responder side observed a RST.
    fn rst_responder(&mut self) {}
}

/// Builds a fresh [`SessionParser`] per session. Modeled on
/// [`crate::ReassemblerFactory`].
///
/// Most parsers can skip implementing this manually: any parser
/// that's `SessionParser + Default + Clone` automatically becomes
/// a factory via the blanket impl below.
pub trait SessionParserFactory<K>: Send + 'static {
    type Parser: SessionParser;
    fn new_parser(&mut self, key: &K) -> Self::Parser;
}

impl<K, P> SessionParserFactory<K> for P
where
    P: SessionParser + Default + Clone,
{
    type Parser = P;
    fn new_parser(&mut self, _key: &K) -> P {
        self.clone()
    }
}

/// Parses a packet-oriented L7 protocol. One instance per flow;
/// receives one L4 payload at a time along with which side sent it.
pub trait DatagramParser: Send + 'static {
    type Message: Send + 'static;

    /// Parse one L4 payload. `side` is the direction relative to
    /// the flow's initiator. Returns any complete messages decoded.
    fn parse(&mut self, payload: &[u8], side: FlowSide) -> Vec<Self::Message>;
}

/// Builds a fresh [`DatagramParser`] per session.
pub trait DatagramParserFactory<K>: Send + 'static {
    type Parser: DatagramParser;
    fn new_parser(&mut self, key: &K) -> Self::Parser;
}

impl<K, P> DatagramParserFactory<K> for P
where
    P: DatagramParser + Default + Clone,
{
    type Parser = P;
    fn new_parser(&mut self, _key: &K) -> P {
        self.clone()
    }
}

/// Output of a [`SessionParser`] or [`DatagramParser`]-backed stream.
///
/// `K` is the flow key, `M` is the parser's message type.
#[derive(Debug, Clone)]
pub enum SessionEvent<K, M> {
    /// First packet of a new session.
    Started { key: K, ts: Timestamp },
    /// Parser emitted a complete L7 message.
    Application {
        key: K,
        side: FlowSide,
        message: M,
        ts: Timestamp,
    },
    /// Session ended (FIN/RST/idle/eviction). Any messages the
    /// parser flushed on close arrive as `Application` events
    /// before the corresponding `Closed`.
    Closed {
        key: K,
        reason: EndReason,
        stats: FlowStats,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Clone)]
    struct CountParser {
        init_bytes: usize,
        resp_bytes: usize,
    }

    impl SessionParser for CountParser {
        type Message = (FlowSide, usize);
        fn feed_initiator(&mut self, b: &[u8]) -> Vec<Self::Message> {
            self.init_bytes += b.len();
            vec![(FlowSide::Initiator, self.init_bytes)]
        }
        fn feed_responder(&mut self, b: &[u8]) -> Vec<Self::Message> {
            self.resp_bytes += b.len();
            vec![(FlowSide::Responder, self.resp_bytes)]
        }
    }

    #[test]
    fn auto_impl_session_parser_factory() {
        // CountParser is Default + Clone + SessionParser → automatic factory.
        let mut f: CountParser = CountParser::default();
        let mut p: CountParser = SessionParserFactory::<u32>::new_parser(&mut f, &7);
        let m = p.feed_initiator(b"abc");
        assert_eq!(m, vec![(FlowSide::Initiator, 3)]);
    }

    #[derive(Default, Clone)]
    struct EchoDgram;
    impl DatagramParser for EchoDgram {
        type Message = (FlowSide, Vec<u8>);
        fn parse(&mut self, payload: &[u8], side: FlowSide) -> Vec<Self::Message> {
            vec![(side, payload.to_vec())]
        }
    }

    #[test]
    fn auto_impl_datagram_parser_factory() {
        let mut f = EchoDgram;
        let mut p: EchoDgram = DatagramParserFactory::<()>::new_parser(&mut f, &());
        let m = p.parse(b"hello", FlowSide::Responder);
        assert_eq!(m, vec![(FlowSide::Responder, b"hello".to_vec())]);
    }
}
