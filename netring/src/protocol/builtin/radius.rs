use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// RADIUS (UDP/1812 auth + 1813 accounting) passive metadata visibility
/// (issue #30).
///
/// `on::<Radius>(|m: &RadiusMessage, ctx|)` fires once per parsed datagram.
/// `Radius` is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP
/// flow.
///
/// Each [`flowscope::radius::RadiusMessage`] exposes the code (Access-Request /
/// Accept / Reject / Accounting-…) and surfaced attributes (e.g. `User-Name`,
/// `NAS-IP-Address`) — the authentication-fabric visibility an NSM needs to
/// spot auth failures, brute force, and rogue NAS clients.
#[derive(Debug, Clone, Copy)]
pub struct Radius;

impl MessageProtocol for Radius {}

impl Protocol for Radius {
    type Message = flowscope::radius::RadiusMessage;
    // Matches flowscope's `radius::PARSER_KIND` ("radius").
    const NAME: &'static str = "radius";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![
            flowscope::radius::RADIUS_AUTH_PORT,
            flowscope::radius::RADIUS_ACCT_PORT,
        ])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Radius::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::radius::RadiusParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_1812_1813() {
        match Radius::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![1812, 1813]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Radius::NAME, flowscope::radius::PARSER_KIND);
    }
}
