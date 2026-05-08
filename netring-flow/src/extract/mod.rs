//! Built-in flow extractors and decap combinators.
//!
//! Available with the `extractors` feature (default-on).
//!
//! - [`FiveTuple`] — protocol + (src, dst) endpoints. Bidirectional
//!   by default (A→B and B→A merged).
//! - [`IpPair`] — IP address pair only; protocol ignored. Useful for
//!   ICMP and fragmented flows.
//! - [`MacPair`] — L2 MAC pair. Useful for ARP, BPDU, LLDP.
//!
//! Decap combinators wrap any extractor and peel one encapsulation
//! layer first:
//!
//! - [`StripVlan<E>`] — strip 802.1Q VLAN tag(s)
//! - [`StripMpls<E>`] — strip MPLS label stack
//! - [`InnerVxlan<E>`] — decap VXLAN, run extractor on inner Ethernet
//! - [`InnerGtpU<E>`] — decap GTP-U, run extractor on inner IP
//!
//! Combinators compose: `StripVlan(InnerVxlan::new(FiveTuple::bidirectional()))`.

mod parse;

pub mod five_tuple;
pub mod ip_pair;
pub mod mac_pair;

pub mod encap_gtp;
pub mod encap_mpls;
pub mod encap_vlan;
pub mod encap_vxlan;

pub use five_tuple::{FiveTuple, FiveTupleKey};
pub use ip_pair::{IpPair, IpPairKey};
pub use mac_pair::{MacPair, MacPairKey};

pub use encap_gtp::InnerGtpU;
pub use encap_mpls::StripMpls;
pub use encap_vlan::StripVlan;
pub use encap_vxlan::InnerVxlan;
