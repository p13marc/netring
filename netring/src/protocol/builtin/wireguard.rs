use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// WireGuard (UDP/51820) passive metadata visibility (issue #30).
///
/// `on::<WireGuard>(|m: &WireGuardMessage, ctx|)` fires once per parsed
/// datagram. `WireGuard` is a [`MessageProtocol`]; its flow lifecycle is the
/// underlying UDP flow.
///
/// Each [`flowscope::wireguard::WireGuardMessage`] exposes the message type
/// (handshake initiation / response / cookie / transport data) and sender/
/// receiver indices — enough to map VPN tunnel endpoints and spot unsanctioned
/// WireGuard tunnels without any decryption.
#[derive(Debug, Clone, Copy)]
pub struct WireGuard;

impl MessageProtocol for WireGuard {}

impl Protocol for WireGuard {
    type Message = flowscope::wireguard::WireGuardMessage;
    // Matches flowscope's `wireguard::PARSER_KIND` ("wireguard").
    const NAME: &'static str = "wireguard";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![flowscope::wireguard::WIREGUARD_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("WireGuard::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::wireguard::WireGuardParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_51820() {
        match WireGuard::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![51820]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(WireGuard::NAME, flowscope::wireguard::PARSER_KIND);
    }
}
