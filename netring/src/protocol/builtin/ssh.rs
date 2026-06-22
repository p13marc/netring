use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// SSH (TCP/22) passive metadata visibility — version banners, the decoded
/// `SSH_MSG_KEXINIT` algorithm name-lists, and the **HASSH** handshake
/// fingerprint (issue #30; the first Tier-2 protocol).
///
/// `on::<Ssh>(|m: &SshMessage, ctx|)` fires once per parsed message.
/// `Ssh` is a [`MessageProtocol`]; its flow lifecycle is the underlying TCP
/// flow. Parsing stops at `SSH_MSG_NEWKEYS` — everything past the key exchange
/// is encrypted.
///
/// HASSH (the SSH analogue of JA3/JA4) lives on the
/// [`SshMessage::KexInit`](flowscope::ssh::SshMessage::KexInit) variant:
///
/// ```no_run
/// # #[cfg(all(feature = "ssh", feature = "tokio"))]
/// # fn demo() {
/// use netring::prelude::*;
/// use flowscope::ssh::SshMessage;
/// Monitor::builder()
///     .interface("eth0")
///     .protocol::<Ssh>()
///     .on::<Ssh>(|m: &SshMessage| {
///         if let SshMessage::KexInit(k) = m {
///             // `k.hassh` is the client HASSH when `k.from_client`, else the
///             // server (HASSHServer) fingerprint.
///             println!("hassh={} client={}", k.hassh, k.from_client);
///         }
///         Ok(())
///     });
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Ssh;

impl MessageProtocol for Ssh {}

impl Protocol for Ssh {
    type Message = flowscope::ssh::SshMessage;
    // Matches flowscope's `ssh::PARSER_KIND` ("ssh").
    const NAME: &'static str = "ssh";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![22])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Ssh::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::ssh::SshParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_22() {
        match Ssh::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![22]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Ssh::NAME, flowscope::ssh::PARSER_KIND);
    }
}
