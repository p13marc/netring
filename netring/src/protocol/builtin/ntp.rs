use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// NTP (UDP/123) passive metadata visibility (issue #30).
///
/// `on::<Ntp>(|m: &NtpMessage, ctx|)` fires once per parsed datagram. `Ntp` is
/// a [`MessageProtocol`]; its flow lifecycle is the underlying UDP flow.
///
/// Each [`flowscope::ntp::NtpMessage`] exposes the mode (client/server/…),
/// stratum, version, and reference id — enough to spot rogue time servers,
/// mode-6/7 amplification (`monlist`-style) abuse, and unexpected NTP talkers.
#[derive(Debug, Clone, Copy)]
pub struct Ntp;

impl MessageProtocol for Ntp {}

impl Protocol for Ntp {
    type Message = flowscope::ntp::NtpMessage;
    // Matches flowscope's `ntp::PARSER_KIND` ("ntp").
    const NAME: &'static str = "ntp";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![123])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Ntp::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::ntp::NtpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_123() {
        match Ntp::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![123]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Ntp::NAME, flowscope::ntp::PARSER_KIND);
    }
}
