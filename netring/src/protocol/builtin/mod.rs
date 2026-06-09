//! Built-in [`Protocol`](crate::protocol::Protocol) marker types.
//!
//! These cover the protocols netring ships parsers for. Third-party
//! crates that implement [`crate::protocol::Protocol`] for their
//! own marker types compose seamlessly with these — no central
//! enum to edit.

mod icmp;
mod tcp;
mod udp;

#[cfg(feature = "dns")]
mod dns;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
mod tls_handshake;

pub use icmp::Icmp;
pub use tcp::Tcp;
pub use udp::Udp;

#[cfg(feature = "dns")]
pub use dns::Dns;
#[cfg(feature = "http")]
pub use http::Http;
#[cfg(feature = "tls")]
pub use tls::Tls;
#[cfg(feature = "tls")]
pub use tls_handshake::TlsHandshake;
