//! `netring-flow-tls` — passive TLS handshake observer for `netring-flow`.
//!
//! Bridges [`tls-parser`](https://crates.io/crates/tls-parser) into
//! `netring-flow`'s reassembler. Receives bytes from the per-flow
//! TCP byte stream, emits parsed [`TlsClientHello`] /
//! [`TlsServerHello`] / [`TlsAlert`] events.
//!
//! # Quick start
//!
//! ```no_run
//! # fn main() {
//! use netring_flow_tls::{TlsFactory, TlsHandler, TlsClientHello};
//!
//! struct Logger;
//! impl TlsHandler for Logger {
//!     fn on_client_hello(&self, h: &TlsClientHello) {
//!         println!("SNI: {:?}, ALPN: {:?}", h.sni, h.alpn);
//!     }
//! }
//!
//! // Wire into a netring FlowStream:
//! //   cap.flow_stream(FiveTuple::bidirectional())
//! //      .with_reassembler(TlsFactory::with_handler(Logger));
//! # }
//! ```
//!
//! # Scope
//!
//! - **Passive** observation only — no decryption, no MITM.
//! - ClientHello, ServerHello, Alert from the unencrypted handshake.
//! - SNI / ALPN / supported versions / cipher list / extension order.
//! - TLS 1.0 — TLS 1.3 (visibility limited after ChangeCipherSpec
//!   in 1.2 and after ServerHello in 1.3 since records are
//!   encrypted onward).
//! - Optional [JA3](https://github.com/salesforce/ja3) fingerprinting
//!   behind the `ja3` feature.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod factory;
#[cfg(feature = "ja3")]
mod fingerprint;
mod parser;
mod types;

pub use factory::{TlsFactory, TlsReassembler};
pub use parser::Error;
pub use types::*;
