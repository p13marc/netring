//! Passive asset inventory (issue #28).
//!
//! `AssetWatch` wraps flowscope's MAC-keyed [`Inventory`](flowscope::Inventory)
//! and the registered `on_asset` handlers. The Monitor's L2/L3 discovery hooks
//! ([`on_arp`](crate::monitor::MonitorBuilder::on_arp) /
//! [`on_ndp`](crate::monitor::MonitorBuilder::on_ndp) /
//! [`on_lldp`](crate::monitor::MonitorBuilder::on_lldp) /
//! [`on_cdp`](crate::monitor::MonitorBuilder::on_cdp)) feed it: each parsed
//! frame is folded into an [`Asset`](flowscope::Asset) keyed by MAC.
//!
//! `on_asset` is an **inventory-event** stream, not a per-packet one — a
//! handler fires only when an observation creates a *new* asset or *changes* an
//! existing one (a freshly-learned IP, hostname, platform, …), staying quiet on
//! repeat-identical frames.
//!
//! v1 feeds from the MAC-carrying frame protocols only. DHCP (richest single
//! source) and the UDP datagram sources (SSDP / NetBIOS-NS / mDNS) are drained
//! on the L7 path and need IP→MAC resolution — a follow-up.

use crate::ctx::Ctx;
use crate::error::Result;
use flowscope::Timestamp;

/// Default LRU capacity when [`asset_inventory`](crate::monitor::MonitorBuilder::asset_inventory)
/// isn't given an explicit one (or `on_asset` enables the inventory implicitly).
pub(crate) const DEFAULT_ASSET_CAPACITY: usize = 4096;

/// Boxed `on_asset` handler: the merged [`flowscope::Asset`] + `&mut Ctx`.
pub(crate) type AssetHandler = Box<dyn Fn(&flowscope::Asset, &mut Ctx<'_>) -> Result<()> + Send>;

/// The Monitor's live asset inventory + `on_asset` handlers.
pub(crate) struct AssetWatch {
    pub(crate) inventory: flowscope::Inventory,
    pub(crate) handlers: Vec<AssetHandler>,
}

impl AssetWatch {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            inventory: flowscope::Inventory::new(capacity),
            handlers: Vec::new(),
        }
    }

    /// Fold one discovery observation into the inventory. Returns the merged
    /// record **only if it's new or changed** — so callers fire `on_asset`
    /// exactly on inventory events, not on every frame.
    pub(crate) fn absorb(
        &mut self,
        update: flowscope::Asset,
        ts: Timestamp,
    ) -> Option<flowscope::Asset> {
        let mac = update.mac;
        let before = self.inventory.get(&mac).cloned();
        let merged = self.inventory.absorb_at(update, ts).clone();
        (before.as_ref() != Some(&merged)).then_some(merged)
    }
}
