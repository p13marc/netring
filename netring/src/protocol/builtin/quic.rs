use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// QUIC (UDP/443) Initial-packet visibility — on-path SNI / ALPN / version from
/// the unprotected ClientHello, *without decryption* (issue #14).
///
/// `on::<Quic>(|m: &QuicInitial, ctx|)` fires once per parsed QUIC Initial.
/// `Quic` is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP
/// flow. flowscope decrypts the QUIC Initial packet via the RFC 9001 §5.2
/// Initial-secret derivation (the secret is a published constant — Initials are
/// "encrypted" but passive-readable) and parses the TLS ClientHello inside.
///
/// Each [`flowscope::QuicInitial`] surfaces `version`, `sni` (the destination
/// hostname an HTTP/3 client is dialing), and `alpn` (`["h3", …]`) — the QUIC
/// analogue of TLS SNI visibility, for the growing share of traffic that has
/// moved off TCP+TLS onto QUIC. (flowscope 0.18 exposes SNI/ALPN/version but no
/// JA4 fingerprint on QUIC yet.)
#[derive(Debug, Clone, Copy)]
pub struct Quic;

impl MessageProtocol for Quic {}

impl Protocol for Quic {
    type Message = flowscope::QuicInitial;
    // Matches flowscope's quic `parser_kind` ("quic").
    const NAME: &'static str = "quic";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![flowscope::quic::QUIC_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Quic::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::quic::QuicUdpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_443() {
        match Quic::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![443]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_is_quic() {
        assert_eq!(Quic::NAME, "quic");
    }
}
