use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// RDP (TCP/3389) passive metadata visibility — the X.224 Connection
/// Request/Confirm exchange before the TLS upgrade (issue #29).
///
/// `on::<Rdp>(|m: &RdpMessage, ctx|)` fires once per parsed message.
/// `Rdp` is a [`MessageProtocol`]; its flow lifecycle is the underlying TCP
/// flow.
///
/// Each [`flowscope::rdp::RdpMessage`] surfaces the lateral-movement signals:
/// `ConnectionRequest::cookie_username` (the `mstshash=` cookie — the targeted
/// account, T1021.001) and the negotiated `RdpProtocols` (an `SSL`-only or
/// `RDP`-legacy selection that drops `HYBRID`/CredSSP is an NLA downgrade —
/// a credential-theft setup).
///
/// Metadata-only by design: parsing stops at the X.224 handshake. Post-upgrade
/// frames are TLS — see [`Tls`](crate::protocol::builtin::Tls) for JA4 on the
/// wrapped handshake.
#[derive(Debug, Clone, Copy)]
pub struct Rdp;

impl MessageProtocol for Rdp {}

impl Protocol for Rdp {
    type Message = flowscope::rdp::RdpMessage;
    const NAME: &'static str = flowscope::rdp::PARSER_KIND;

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![flowscope::rdp::RDP_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Rdp::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::rdp::RdpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_3389() {
        match Rdp::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![3389]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_is_rdp() {
        assert_eq!(Rdp::NAME, "rdp");
    }
}
