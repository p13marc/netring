use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// STUN (UDP/3478) passive metadata visibility (issue #30).
///
/// `on::<Stun>(|m: &StunMessage, ctx|)` fires once per parsed datagram. `Stun`
/// is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP flow.
///
/// Each [`flowscope::stun::StunMessage`] exposes the message type
/// (Binding request/response, …) and class — the NAT-traversal signaling that
/// precedes WebRTC / P2P / VoIP media and is a useful exfil-channel indicator.
#[derive(Debug, Clone, Copy)]
pub struct Stun;

impl MessageProtocol for Stun {}

impl Protocol for Stun {
    type Message = flowscope::stun::StunMessage;
    // Matches flowscope's `stun::PARSER_KIND` ("stun").
    const NAME: &'static str = "stun";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![flowscope::stun::STUN_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Stun::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::stun::StunParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_3478() {
        match Stun::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![3478]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Stun::NAME, flowscope::stun::PARSER_KIND);
    }
}
