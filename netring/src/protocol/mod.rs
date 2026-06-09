//! Unified multi-protocol event surface.
//!
//! [`ProtocolEvent<K>`] is a sum-type over the lifecycle events
//! that come out of flowscope's `FlowTracker` plus the L7 messages
//! emitted by HTTP / DNS / TLS parsers. It's the canonical event
//! type for **multi-protocol anomaly correlation** — see
//! [`crate::correlate`] for the primitives that consume it.
//!
//! [`ProtocolMonitor<K>`] is the entry point: declare which
//! protocols you care about (`flow()`, `http()`, `dns()`, `tls()`),
//! the monitor orchestrates one filtered `AsyncCapture` per
//! protocol and yields events through a unified async stream.
//!
//! ```no_run
//! # #[cfg(all(feature = "tokio", feature = "http", feature = "dns"))]
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use futures::StreamExt;
//! use netring::flow::extract::FiveTuple;
//! use netring::protocol::{ProtocolEvent, ProtocolMessage, ProtocolMonitorBuilder};
//!
//! let mut monitor = ProtocolMonitorBuilder::new()
//!     .interface("eth0")
//!     .flow()
//!     .http()
//!     .dns()
//!     .build(FiveTuple::bidirectional())?;
//!
//! while let Some(evt) = monitor.next().await {
//!     match evt? {
//!         ProtocolEvent::FlowStarted { .. }
//!         | ProtocolEvent::FlowEnded { .. } => { /* flow lifecycle */ }
//!         ProtocolEvent::Message { parser_kind, message: ProtocolMessage::Http(_), .. } => {
//!             let _ = parser_kind;
//!         }
//!         ProtocolEvent::Message { message: ProtocolMessage::Dns(_), .. } => {
//!             /* dns query/response/unanswered */
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(()) }
//! ```

mod event;
mod monitor;

pub mod builtin;
pub mod event_typed;

pub use event::{ProtocolEvent, ProtocolMessage};
pub use event_typed::{
    AnyFlowAnomaly, Event, FlowEnded, FlowEstablished, FlowStarted, Side, TcpInfo, Tick,
};
pub use monitor::{ProtocolMonitor, ProtocolMonitorBuilder};

// ─── Plugin layer (netring 0.20, Phase A) ──────────────────────────────────
//
// The `Protocol` trait + supporting types define a protocol-agnostic plugin
// layer. Downstream crates implement `Protocol` for their own marker types
// and register them via the (forthcoming) `Monitor::builder().protocol::<P>()`
// API.
//
// In Phase A these types are defined but NOT yet consumed by the existing
// `ProtocolMonitorBuilder`. Phase B introduces the `Monitor` builder that
// uses them.

/// A protocol the monitor can observe.
///
/// Implementors are usually zero-sized marker types (`struct Http;`).
/// The marker is used as a type-level identifier; the runtime
/// dispatch key is its `TypeId`.
///
/// `'static` is required because dispatch is keyed by `TypeId`.
/// This forecloses lifetime-parameterized marker types — not a
/// real limitation since markers are typically ZSTs.
///
/// Built-in markers ship in [`builtin`]; downstream crates can
/// add their own without editing netring.
pub trait Protocol: Send + Sync + 'static {
    /// The typed message this protocol's parser emits. Must be
    /// `'static` (owning) — the framework downcasts via `Any`,
    /// which requires `'static`.
    type Message: Send + Sync + 'static;

    /// Stable identifier, used for metrics labels, log targets,
    /// and the `parser_kind` field on the low-level Stream API.
    /// Convention: lowercase, hyphenated. Examples: `"http/1"`,
    /// `"dns-udp"`, `"tls-handshake"`. Matches flowscope's
    /// `parser_kinds::*` constants where applicable.
    const NAME: &'static str;

    /// How packets get routed to this protocol's parser.
    fn dispatch() -> Dispatch;

    /// Construct the parser instance — a flowscope session or
    /// datagram parser ready to register against the typed
    /// `Driver<E>`. Called once at builder time.
    ///
    /// Lifecycle-only markers ([`builtin::Tcp`] / [`builtin::Udp`])
    /// return `Err`; the builder treats [`Dispatch::AllTcp`] /
    /// [`Dispatch::AllUdp`] as "no parser slot to register; just
    /// record the marker for typed lifecycle event filtering."
    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError>;
}

/// flowscope 0.11 has two parser-trait flavors. A [`Protocol`]
/// impl declares which one it produces; netring's builder routes
/// to the matching `Driver<E>` registration method.
pub enum ParserKind<M> {
    /// TCP-shaped parser (HTTP, DNS-over-TCP, TLS, …).
    Session(Box<dyn flowscope::SessionParser<Message = M>>),
    /// UDP / ICMP-shaped parser (DNS-over-UDP, ICMP, …).
    Datagram(Box<dyn flowscope::DatagramParser<Message = M>>),
}

impl<M> std::fmt::Debug for ParserKind<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserKind::Session(_) => {
                f.write_str("ParserKind::Session(<flowscope::SessionParser>)")
            }
            ParserKind::Datagram(_) => {
                f.write_str("ParserKind::Datagram(<flowscope::DatagramParser>)")
            }
        }
    }
}

/// How a protocol selects packets for its parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Dispatch {
    /// Match TCP flows on these ports.
    Tcp(Vec<u16>),
    /// Match UDP flows on these ports.
    Udp(Vec<u16>),
    /// Match all ICMP / ICMPv6 datagrams.
    Icmp,
    /// All TCP flows regardless of port — the L4-lifecycle case
    /// for the [`builtin::Tcp`] marker.
    AllTcp,
    /// All UDP flows regardless of port — the [`builtin::Udp`] marker.
    AllUdp,
    /// Port-agnostic dispatch via a signature function over the
    /// first ≤64 payload bytes. The function returns whether the
    /// packet matches; matching flows pin to the parser.
    Signature(fn(&[u8]) -> SignatureMatch),
}

/// Result of a signature function. `Match` pins the flow to this
/// protocol's parser; `NoMatch` skips it; `NeedMoreData` says
/// "I need more bytes" — the dispatcher keeps probing until budget
/// runs out.
///
/// Mirrors [`flowscope::detect::signatures::SignatureMatch`] —
/// the [`From`] impl converts losslessly so netring users can
/// pass flowscope signature functions directly into
/// [`Dispatch::Signature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMatch {
    /// Bytes definitively match this protocol.
    Match,
    /// Bytes definitively do not match.
    NoMatch,
    /// Not enough bytes to decide — re-check with more.
    NeedMoreData,
}

impl From<flowscope::detect::signatures::SignatureMatch> for SignatureMatch {
    fn from(s: flowscope::detect::signatures::SignatureMatch) -> Self {
        use flowscope::detect::signatures::SignatureMatch as Fs;
        match s {
            Fs::Match => SignatureMatch::Match,
            Fs::NoMatch => SignatureMatch::NoMatch,
            Fs::NeedMoreData => SignatureMatch::NeedMoreData,
        }
    }
}

/// Error type for [`Protocol::parser`]. Most parsers are infallible
/// to construct; flowscope parsers that take config can fail.
/// Lifecycle-only markers (Tcp, Udp) use this to indicate "no
/// parser slot needed — handled by the central flow tracker."
#[derive(Debug, thiserror::Error)]
#[error("protocol parser init failed: {0}")]
pub struct ProtocolInitError(pub String);

/// Convenience alias — the flow key produced by
/// [`flowscope::extract::FiveTuple`]. Most user code names this
/// rather than the longer fully-qualified path.
pub type FlowKey = flowscope::extract::FiveTupleKey;

#[cfg(test)]
mod plugin_tests {
    use super::*;

    #[test]
    fn signature_match_from_flowscope_roundtrip() {
        use flowscope::detect::signatures::SignatureMatch as Fs;
        assert_eq!(SignatureMatch::from(Fs::Match), SignatureMatch::Match);
        assert_eq!(SignatureMatch::from(Fs::NoMatch), SignatureMatch::NoMatch);
        assert_eq!(
            SignatureMatch::from(Fs::NeedMoreData),
            SignatureMatch::NeedMoreData
        );
    }

    #[test]
    fn dispatch_is_clone_and_debug() {
        let d = Dispatch::Tcp(vec![80, 8080]);
        let _ = format!("{d:?}");
        let _ = d.clone();
    }

    #[test]
    fn protocol_init_error_displays() {
        let e = ProtocolInitError("config missing".into());
        assert!(format!("{e}").contains("config missing"));
    }
}
