//! LLDP (IEEE 802.1AB) link-layer discovery surfacing (issue #28).
//!
//! LLDP is an L2 protocol (EtherType `0x88cc`, link-local multicast) with no
//! 5-tuple, so — like [`arp`](crate::monitor::arp) / [`ndp`](crate::monitor::ndp)
//! — it's parsed per-frame in the Monitor's zero-copy drain (and the pcap
//! replay loop) rather than through the flow driver. Each frame announces a
//! switch/router/AP neighbor: its chassis id, port id, system name, and
//! capabilities — the network-device half of an asset inventory.
//!
//! There's no anomaly pipeline in v1: `LldpWatch` just feeds every parsed
//! [`flowscope::LldpMessage`] to the `on_lldp` handlers.

use crate::ctx::Ctx;
use crate::error::Result;

/// Boxed `on_lldp` handler: every parsed [`flowscope::LldpMessage`] + `&mut Ctx`.
pub(crate) type LldpMsgHandler =
    Box<dyn Fn(&flowscope::LldpMessage, &mut Ctx<'_>) -> Result<()> + Send>;

/// The Monitor's live LLDP state — just the registered `on_lldp` handlers.
/// `Some` on the [`Monitor`](crate::monitor::Monitor) once any LLDP hook is
/// registered; the per-frame parse is armed only then.
pub(crate) struct LldpWatch {
    pub(crate) msg_handlers: Vec<LldpMsgHandler>,
}

impl LldpWatch {
    pub(crate) fn new() -> Self {
        Self {
            msg_handlers: Vec::new(),
        }
    }
}
