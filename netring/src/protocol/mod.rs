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

pub use event::{ProtocolEvent, ProtocolMessage};
pub use monitor::{ProtocolMonitor, ProtocolMonitorBuilder};
