use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// SMB2/SMB3 (TCP/445) passive metadata visibility — the primary
/// lateral-movement channel on Windows networks (issue #29).
///
/// `on::<Smb>(|m: &SmbMessage, ctx|)` fires once per parsed SMB message.
/// The flow lifecycle is the underlying TCP flow (`FlowStarted<Tcp>`), so
/// `Smb` is a [`MessageProtocol`], not a `FlowProtocol`.
///
/// Each [`flowscope::smb::SmbMessage`] carries the lateral-movement signals
/// passive defenders care about: `tree_connect_is_admin_share` (C$ / ADMIN$ /
/// IPC$), `create_is_admin_named_pipe` (svcctl / lsarpc / samr / spoolss …),
/// `dcerpc_bind_uuids` (DCSync via the drsuapi interface), and `ntlm_auth`
/// (domain / username / workstation).
#[derive(Debug, Clone, Copy)]
pub struct Smb;

impl MessageProtocol for Smb {}

impl Protocol for Smb {
    type Message = flowscope::smb::SmbMessage;
    // Matches flowscope's `smb::parser_kind()` ("smb"); kept as a literal
    // because that accessor is a fn, not a const.
    const NAME: &'static str = "smb";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![flowscope::smb::SMB_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Smb::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::smb::SmbParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_445() {
        match Smb::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![445]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Smb::NAME, flowscope::smb::parser_kind());
    }
}
