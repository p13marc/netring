//! Built-in [`Protocol`](crate::protocol::Protocol) marker types.
//!
//! These cover the protocols netring ships parsers for. Third-party
//! crates that implement [`crate::protocol::Protocol`] for their
//! own marker types compose seamlessly with these — no central
//! enum to edit.

mod icmp;
mod tcp;
mod udp;

#[cfg(feature = "dhcp")]
mod dhcp;
#[cfg(feature = "dns")]
mod dns;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "kerberos")]
mod kerberos;
#[cfg(feature = "ldap")]
mod ldap;
#[cfg(feature = "netbios-ns")]
mod nbns;
#[cfg(feature = "rdp")]
mod rdp;
#[cfg(feature = "smb")]
mod smb;
#[cfg(feature = "ssdp")]
mod ssdp;
#[cfg(feature = "ssh")]
mod ssh;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
mod tls_handshake;

pub use icmp::Icmp;
pub use tcp::Tcp;
pub use udp::Udp;

#[cfg(feature = "dhcp")]
pub use dhcp::Dhcp;
#[cfg(feature = "dns")]
pub use dns::Dns;
#[cfg(feature = "http")]
pub use http::Http;
#[cfg(feature = "kerberos")]
pub use kerberos::Kerberos;
#[cfg(feature = "ldap")]
pub use ldap::Ldap;
#[cfg(feature = "netbios-ns")]
pub use nbns::Nbns;
#[cfg(feature = "rdp")]
pub use rdp::Rdp;
#[cfg(feature = "smb")]
pub use smb::Smb;
#[cfg(feature = "ssdp")]
pub use ssdp::Ssdp;
#[cfg(feature = "ssh")]
pub use ssh::Ssh;
#[cfg(feature = "tls")]
pub use tls::Tls;
#[cfg(feature = "tls")]
pub use tls_handshake::TlsHandshake;
