use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// SMTP (TCP/25 + 587 submission) passive metadata visibility (issue #30).
///
/// `on::<Smtp>(|m: &SmtpMessage, ctx|)` fires once per parsed command/reply.
/// `Smtp` is a [`MessageProtocol`]; its flow lifecycle is the underlying TCP
/// flow.
///
/// Each [`flowscope::smtp::SmtpMessage`] exposes the command (HELO/MAIL/RCPT/
/// AUTH/STARTTLS/…), the envelope sender/recipients, and whether the session
/// upgraded to TLS — the inputs to mail-exfil and spam-relay detection.
#[derive(Debug, Clone, Copy)]
pub struct Smtp;

impl MessageProtocol for Smtp {}

impl Protocol for Smtp {
    type Message = flowscope::smtp::SmtpMessage;
    // Matches flowscope's `smtp::PARSER_KIND` ("smtp").
    const NAME: &'static str = "smtp";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![
            flowscope::smtp::SMTP_PORT,
            flowscope::smtp::SMTP_SUBMISSION_PORT,
        ])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Smtp::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::smtp::SmtpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_25_587() {
        match Smtp::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![25, 587]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Smtp::NAME, flowscope::smtp::PARSER_KIND);
    }
}
