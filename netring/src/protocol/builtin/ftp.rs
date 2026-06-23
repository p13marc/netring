use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// FTP control channel (TCP/21) passive metadata visibility (issue #30).
///
/// `on::<Ftp>(|m: &FtpMessage, ctx|)` fires once per parsed control-channel
/// command/reply. `Ftp` is a [`MessageProtocol`]; its flow lifecycle is the
/// underlying TCP flow.
///
/// Each [`flowscope::ftp::FtpMessage`] exposes the command (USER/PASS/RETR/
/// STOR/…) or reply code — cleartext credentials, file transfers, and the
/// PORT/PASV data-channel negotiation that data-loss tooling keys on.
#[derive(Debug, Clone, Copy)]
pub struct Ftp;

impl MessageProtocol for Ftp {}

impl Protocol for Ftp {
    type Message = flowscope::ftp::FtpMessage;
    // Matches flowscope's `ftp::PARSER_KIND` ("ftp").
    const NAME: &'static str = "ftp";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![flowscope::ftp::FTP_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Ftp::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::ftp::FtpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_21() {
        match Ftp::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![21]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Ftp::NAME, flowscope::ftp::PARSER_KIND);
    }
}
