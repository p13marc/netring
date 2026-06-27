//! Packet-tier subscription runtime (0.25 Phase A1c).
//!
//! The packet tier is the **new** capability: a handler that sees *every*
//! captured frame as a borrowed [`PacketView`], filtered by a [`Predicate`],
//! **before** flow tracking. It runs inside the zero-copy drain (the run
//! loop's `drain_batch` callback), so the handler is synchronous — it must not
//! block or `.await`. The whole path is gated on "are there any packet subs",
//! so monitors that register none keep the `track_into`-only hot loop (dhat
//! stays `Δ 0`).
//!
//! This is also where the Phase A3 kernel pushdown attaches: the union of all
//! packet subs' kernel-pushable conjunctions compiles to the cBPF / XDP filter
//! so most non-matching frames never reach this userspace tier at all.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::{FlowExtractor, L4Proto, PacketView};

use super::predicate::{FieldSource, Predicate};
use crate::ctx::Ctx;
use crate::error::Result;

/// A packet-tier handler: a borrowed [`PacketView`] for the current frame plus
/// `&mut Ctx` for emitting anomalies / touching state. Synchronous (runs in
/// the zero-copy drain before tracking).
pub type PacketHandler =
    Arc<dyn for<'a, 'c> Fn(&PacketView<'a>, &mut Ctx<'c>) -> Result<()> + Send + Sync>;

/// A built packet subscription: the filter [`Predicate`] paired with its
/// handler. Produced by `packet()…​.to(handler)` and registered through
/// [`MonitorBuilder::subscribe`](crate::monitor::MonitorBuilder::subscribe).
///
/// The predicate lives behind a lock-free [`ArcSwap`] cell so it can be
/// hot-reloaded on a running monitor via
/// [`ReloadHandle::set_packet_filter`](crate::monitor::ReloadHandle::set_packet_filter)
/// (issue #53) — the per-frame drain reads it with an allocation-free
/// `load()`, so the zero-copy hot path stays `Δ 0`.
#[derive(Clone)]
pub struct PacketSubscription {
    pub(crate) predicate: Arc<ArcSwap<Predicate>>,
    pub(crate) handler: PacketHandler,
}

impl std::fmt::Debug for PacketSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketSubscription")
            .field("predicate", &self.predicate.load())
            .field("handler", &"<fn>")
            .finish()
    }
}

/// 5-tuple field source for packet-tier predicate evaluation. Built from one
/// [`FiveTuple::directional`] extraction so `key.a` is the wire source and
/// `key.b` the destination — no orientation juggling.
///
/// VLAN id is not surfaced by the extractor, so `vlan()` filters evaluate to
/// `false` here; they are kernel-side (Phase A3) where the tag is visible.
pub(crate) struct PacketFields {
    proto: L4Proto,
    src: SocketAddr,
    dst: SocketAddr,
}

impl PacketFields {
    /// Extract the 5-tuple from a frame. `None` for frames the extractor
    /// skips (ARP, malformed, non-IP) — those match no packet sub.
    pub(crate) fn extract(
        view: PacketView<'_>,
        extractor: &FiveTuple,
    ) -> Option<(FiveTupleKey, Self)> {
        let ex = extractor.extract(view)?;
        let key = ex.key;
        Some((
            key,
            Self {
                proto: ex.l4.unwrap_or(key.proto),
                src: key.a,
                dst: key.b,
            },
        ))
    }
}

impl FieldSource for PacketFields {
    fn l4proto(&self) -> Option<L4Proto> {
        Some(self.proto)
    }
    fn src_port(&self) -> Option<u16> {
        Some(self.src.port())
    }
    fn dst_port(&self) -> Option<u16> {
        Some(self.dst.port())
    }
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.src.ip())
    }
    fn dst_ip(&self) -> Option<IpAddr> {
        Some(self.dst.ip())
    }
}

/// A directional extractor for packet-tier field extraction — `a`=src, `b`=dst.
/// Stateless and cheap to construct; kept beside the run loop's tracker.
pub(crate) fn packet_field_extractor() -> FiveTuple {
    FiveTuple::directional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::subscription::predicate::Atom;

    fn udp_frame(src_port: u16, dst_port: u16) -> Vec<u8> {
        let payload = [0u8; 4];
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst mac
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
        f.extend_from_slice(&[0x08, 0x00]); // ipv4
        f.push(0x45);
        f.push(0);
        let ip_total = (20 + 8 + payload.len()) as u16;
        f.extend_from_slice(&ip_total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.push(64);
        f.push(17); // udp
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1]); // src ip
        f.extend_from_slice(&[10, 0, 0, 2]); // dst ip
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&payload);
        f
    }

    #[test]
    fn packet_fields_extract_directional_src_dst() {
        let frame = udp_frame(54321, 53);
        let view = PacketView::new(&frame, flowscope::Timestamp::new(0, 0));
        let (_key, fields) =
            PacketFields::extract(view, &packet_field_extractor()).expect("udp frame extracts");
        assert_eq!(fields.l4proto(), Some(L4Proto::Udp));
        assert_eq!(fields.src_port(), Some(54321));
        assert_eq!(fields.dst_port(), Some(53));
        assert_eq!(fields.src_ip(), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(fields.dst_ip(), Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn predicate_evaluates_against_packet_fields() {
        let frame = udp_frame(54321, 53);
        let view = PacketView::new(&frame, flowscope::Timestamp::new(0, 0));
        let (_k, fields) = PacketFields::extract(view, &packet_field_extractor()).unwrap();
        // udp AND dst_port 53 → matches; tcp → doesn't.
        let dns =
            Predicate::Atom(Atom::Proto(L4Proto::Udp)).and(Predicate::Atom(Atom::DstPort(53)));
        assert!(dns.eval(&fields));
        assert!(!Predicate::Atom(Atom::Proto(L4Proto::Tcp)).eval(&fields));
    }
}
