//! CDP (Cisco Discovery Protocol) link-layer discovery surfacing (issue #28).
//!
//! CDP is an L2 protocol carried over IEEE 802.3 LLC/SNAP (dst MAC
//! `01:00:0c:cc:cc:cc`, OUI `00:00:0c`, PID `0x2000`) with no 5-tuple, so —
//! like [`arp`](crate::monitor::arp) / [`lldp`](crate::monitor::lldp) — it's
//! parsed per-frame in the Monitor's zero-copy drain (and the pcap replay
//! loop). Each frame announces a Cisco neighbor: device id, platform, software
//! version, capabilities, and addresses.
//!
//! Unlike LLDP (a clean EtherType term), CDP rides 802.3 LLC/SNAP whose L2
//! "EtherType" field is a frame *length* — it can't be expressed in the cBPF
//! atom model, so arming a CDP hook forces the kernel prefilter to capture-all
//! (fail-open). See [`MonitorBuilder::on_cdp`](crate::monitor::MonitorBuilder::on_cdp).
//!
//! There's no anomaly pipeline in v1: `CdpWatch` just feeds every parsed
//! [`flowscope::CdpMessage`] to the `on_cdp` handlers.

use crate::ctx::Ctx;
use crate::error::Result;

/// Boxed `on_cdp` handler: every parsed [`flowscope::CdpMessage`] + `&mut Ctx`.
pub(crate) type CdpMsgHandler =
    Box<dyn Fn(&flowscope::CdpMessage, &mut Ctx<'_>) -> Result<()> + Send>;

/// The Monitor's live CDP state — just the registered `on_cdp` handlers.
pub(crate) struct CdpWatch {
    pub(crate) msg_handlers: Vec<CdpMsgHandler>,
}

impl CdpWatch {
    pub(crate) fn new() -> Self {
        Self {
            msg_handlers: Vec::new(),
        }
    }
}
