use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// TFTP (UDP/69) passive metadata visibility (issue #30).
///
/// `on::<Tftp>(|m: &TftpMessage, ctx|)` fires once per parsed datagram. `Tftp`
/// is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP flow.
///
/// Each [`flowscope::tftp::TftpMessage`] exposes the opcode (RRQ/WRQ/DATA/…),
/// the requested filename, and transfer mode — TFTP is unauthenticated and a
/// common config-exfil / firmware-staging vector worth surfacing on a network.
#[derive(Debug, Clone, Copy)]
pub struct Tftp;

impl MessageProtocol for Tftp {}

impl Protocol for Tftp {
    type Message = flowscope::tftp::TftpMessage;
    // Matches flowscope's `tftp::PARSER_KIND` ("tftp").
    const NAME: &'static str = "tftp";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![flowscope::tftp::TFTP_SERVER_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Tftp::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::tftp::TftpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_69() {
        match Tftp::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![69]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Tftp::NAME, flowscope::tftp::PARSER_KIND);
    }
}
