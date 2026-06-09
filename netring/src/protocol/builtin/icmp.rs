//! ICMP message parser marker.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// ICMPv4 + ICMPv6 message parser. Surfaces `IcmpMessage` events
/// including `inner: Option<IcmpInner>` on error variants — the
/// cross-protocol correlation primitive that ties an ICMP error
/// back to the originating TCP/UDP flow.
#[derive(Debug, Clone, Copy)]
pub struct Icmp;

#[cfg(feature = "icmp")]
impl Protocol for Icmp {
    type Message = flowscope::icmp::IcmpMessage;
    const NAME: &'static str = flowscope::parser_kinds::ICMP;

    fn dispatch() -> Dispatch {
        Dispatch::Icmp
    }

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Datagram(Box::new(
            flowscope::icmp::IcmpParser::new(),
        )))
    }
}

#[cfg(all(test, feature = "icmp"))]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_icmp() {
        assert!(matches!(<Icmp as Protocol>::dispatch(), Dispatch::Icmp));
    }

    #[test]
    fn name_matches_flowscope_parser_kind() {
        assert_eq!(<Icmp as Protocol>::NAME, flowscope::parser_kinds::ICMP);
    }

    #[test]
    fn parser_constructs_successfully() {
        let p = <Icmp as Protocol>::parser();
        assert!(p.is_ok());
        assert!(matches!(p.unwrap(), ParserKind::Datagram(_)));
    }
}
