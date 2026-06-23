//! Passive TCP/OS fingerprinting — p0f (issue #31).
//!
//! Every TCP **SYN** / **SYN-ACK** carries OS-specific stack defaults (initial
//! TTL, window size, MSS, option layout, quirks) that identify the sender's
//! operating system without touching the payload. flowscope's
//! [`tcp_fingerprint`](flowscope::tcp_fingerprint) extracts them per-packet;
//! the Monitor calls it in the zero-copy drain (and the pcap replay loop) like
//! [`arp`](crate::monitor::arp) / [`ndp`](crate::monitor::ndp), since the
//! fingerprint is a per-packet artifact, not a flow message.
//!
//! [`MonitorBuilder::on_p0f`](crate::monitor::MonitorBuilder::on_p0f) hands each
//! handler a [`flowscope::TcpFingerprint`] — its `direction` (Syn = client,
//! SynAck = server), the extracted fields, and
//! [`to_p0f_signature`](flowscope::TcpFingerprint::to_p0f_signature) (the
//! canonical p0f-3 `ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass`
//! string for matching against a p0f database).
//!
//! There's no anomaly pipeline in v1: `P0fWatch` feeds every parsed
//! fingerprint to the `on_p0f` handlers.

use crate::ctx::Ctx;
use crate::error::Result;

/// Boxed `on_p0f` handler: every extracted [`flowscope::TcpFingerprint`] + `&mut Ctx`.
pub(crate) type P0fHandler =
    Box<dyn Fn(&flowscope::TcpFingerprint, &mut Ctx<'_>) -> Result<()> + Send>;

/// The Monitor's live p0f state — just the registered `on_p0f` handlers.
pub(crate) struct P0fWatch {
    pub(crate) handlers: Vec<P0fHandler>,
}

impl P0fWatch {
    pub(crate) fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }
}
