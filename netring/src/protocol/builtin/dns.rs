//! DNS-over-UDP protocol marker.
//!
//! DNS-over-TCP is intentionally not a built-in marker; users who
//! want it ship their own `Protocol` impl with the parser they want.

use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

// 0.22 R1: DNS is a message protocol (`on::<Dns>` fires `DnsMessage`);
// its flow lifecycle is the underlying UDP flow.
impl MessageProtocol for Dns {}

/// DNS over UDP. Default port: 53. Uses
/// [`flowscope::dns::DnsUdpParser::with_correlation`] so responses
/// carry an `elapsed` (RTT) field and unanswered queries surface
/// from `on_tick`.
#[derive(Debug, Clone, Copy)]
pub struct Dns;

impl Protocol for Dns {
    type Message = flowscope::dns::DnsMessage;
    const NAME: &'static str = flowscope::parser_kinds::DNS_UDP;

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![53])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Dns::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::dns::DnsUdpParser::with_correlation(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_udp_53() {
        match <Dns as Protocol>::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![53]),
            other => panic!("expected Dispatch::Udp([53]), got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_parser_kind() {
        assert_eq!(<Dns as Protocol>::NAME, flowscope::parser_kinds::DNS_UDP);
    }

    #[test]
    fn register_returns_handle() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        let h = <Dns as Protocol>::register(&mut b);
        assert!(h.is_ok());
    }
}
