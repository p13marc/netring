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
#[cfg(feature = "dnp3")]
mod dnp3;
#[cfg(feature = "dns")]
mod dns;
#[cfg(feature = "ftp")]
mod ftp;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "kerberos")]
mod kerberos;
#[cfg(feature = "ldap")]
mod ldap;
#[cfg(feature = "modbus")]
mod modbus;
#[cfg(feature = "netbios-ns")]
mod nbns;
#[cfg(feature = "ntp")]
mod ntp;
#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "radius")]
mod radius;
#[cfg(feature = "rdp")]
mod rdp;
#[cfg(feature = "smb")]
mod smb;
#[cfg(feature = "smtp")]
mod smtp;
#[cfg(feature = "snmp")]
mod snmp;
#[cfg(feature = "ssdp")]
mod ssdp;
#[cfg(feature = "ssh")]
mod ssh;
#[cfg(feature = "stun")]
mod stun;
#[cfg(feature = "tftp")]
mod tftp;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
mod tls_handshake;
#[cfg(feature = "wireguard")]
mod wireguard;

pub use icmp::Icmp;
pub use tcp::Tcp;
pub use udp::Udp;

#[cfg(feature = "dhcp")]
pub use dhcp::Dhcp;
#[cfg(feature = "dnp3")]
pub use dnp3::Dnp3;
#[cfg(feature = "dns")]
pub use dns::Dns;
#[cfg(feature = "ftp")]
pub use ftp::Ftp;
#[cfg(feature = "http")]
pub use http::Http;
#[cfg(feature = "kerberos")]
pub use kerberos::Kerberos;
#[cfg(feature = "ldap")]
pub use ldap::Ldap;
#[cfg(feature = "modbus")]
pub use modbus::Modbus;
#[cfg(feature = "netbios-ns")]
pub use nbns::Nbns;
#[cfg(feature = "ntp")]
pub use ntp::Ntp;
#[cfg(feature = "quic")]
pub use quic::Quic;
#[cfg(feature = "radius")]
pub use radius::Radius;
#[cfg(feature = "rdp")]
pub use rdp::Rdp;
#[cfg(feature = "smb")]
pub use smb::Smb;
#[cfg(feature = "smtp")]
pub use smtp::Smtp;
#[cfg(feature = "snmp")]
pub use snmp::Snmp;
#[cfg(feature = "ssdp")]
pub use ssdp::Ssdp;
#[cfg(feature = "ssh")]
pub use ssh::Ssh;
#[cfg(feature = "stun")]
pub use stun::Stun;
#[cfg(feature = "tftp")]
pub use tftp::Tftp;
#[cfg(feature = "tls")]
pub use tls::Tls;
#[cfg(feature = "tls")]
pub use tls_handshake::TlsHandshake;
#[cfg(feature = "wireguard")]
pub use wireguard::WireGuard;
