//! `netring-flow-http` — passive HTTP/1.x observation for `netring-flow`.
//!
//! Bridges `httparse`'s zero-copy HTTP/1.x parser into the
//! `netring-flow` reassembler. Receives bytes from the per-flow
//! reassembler, emits parsed [`HttpRequest`] / [`HttpResponse`]
//! events.
//!
//! # Quick start
//!
//! ```no_run
//! # fn main() {
//! use netring_flow_http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
//!
//! struct Logger;
//! impl HttpHandler for Logger {
//!     fn on_request(&self, req: &HttpRequest) {
//!         println!("{} {}", req.method, req.path);
//!     }
//!     fn on_response(&self, resp: &HttpResponse) {
//!         println!("  -> {} {}", resp.status, resp.reason);
//!     }
//! }
//!
//! // Wire into a netring FlowStream:
//! //   cap.flow_stream(FiveTuple::bidirectional())
//! //      .with_reassembler(HttpFactory::with_handler(Logger));
//! # }
//! ```
//!
//! # Scope
//!
//! - HTTP/1.0 and HTTP/1.1.
//! - Request line + headers + body via Content-Length.
//! - Pipelined requests on one connection.
//! - HTTP/2 / HTTP/3: out of scope (see crate README).
//! - Chunked Transfer-Encoding: deferred (v0.2). HEAD-correlation:
//!   not done; document.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod factory;
mod parser;
mod session;
mod types;

pub use factory::{HttpFactory, HttpReassembler};
pub use parser::Error;
pub use session::{HttpMessage, HttpParser};
pub use types::{HttpConfig, HttpHandler, HttpRequest, HttpResponse, HttpVersion};
