//! `netring-flow-dns` — passive DNS observer for `netring-flow`.
//!
//! Parses DNS query/response messages observed in UDP/53 traffic
//! and emits events via a user-supplied [`DnsHandler`]. Optionally
//! correlates queries with responses by 16-bit transaction ID,
//! per-flow.
//!
//! # Quick start (UDP/53 only)
//!
//! ```no_run
//! # fn main() {
//! use netring_flow_dns::{parse_message, DnsParseResult};
//!
//! // Inside your packet loop, after you've identified a UDP/53 payload:
//! let payload: &[u8] = b"";  // your UDP payload
//! match parse_message(payload) {
//!     Ok(DnsParseResult::Query(q)) => println!("query: {} questions", q.questions.len()),
//!     Ok(DnsParseResult::Response(r)) => println!("response: rcode={:?}", r.rcode),
//!     Err(_e) => {}  // malformed — ignore
//! }
//! # }
//! ```
//!
//! For fully-integrated flow tracking + DNS event dispatch, see
//! [`DnsUdpObserver`] which wraps a [`netring_flow::FlowExtractor`].
//!
//! # Scope
//!
//! - **UDP/53 only** in v1. TCP/53 (large responses, AXFR/IXFR)
//!   and DoT (TLS/853) are deferred to v0.2.
//! - **Passive** — no resolution, no validation.
//! - DNSSEC: RRSIG/DNSKEY are surfaced as [`DnsRdata::Other`] with
//!   the raw rdata; we don't validate signatures.
//! - **Common record types** decoded: A, AAAA, CNAME, NS, PTR, MX,
//!   TXT. Everything else: `DnsRdata::Other { rtype, data }`.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod correlator;
mod observer;
mod parser;
mod types;

pub use correlator::Correlator;
pub use observer::DnsUdpObserver;
pub use parser::{DnsParseResult, parse_message, parse_message_at};
pub use types::*;

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid DNS message: {0}")]
    Parse(String),
}
