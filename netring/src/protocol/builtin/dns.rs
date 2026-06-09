//! DNS-over-UDP protocol marker.
//!
//! DNS-over-TCP is intentionally not a built-in marker; users who
//! want it ship their own `Protocol` impl with the parser they want.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

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

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Datagram(Box::new(
            flowscope::dns::DnsUdpParser::with_correlation(),
        )))
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
    fn parser_constructs_successfully() {
        assert!(matches!(
            <Dns as Protocol>::parser().unwrap(),
            ParserKind::Datagram(_)
        ));
    }
}
