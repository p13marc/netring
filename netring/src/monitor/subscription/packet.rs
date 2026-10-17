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
use crate::config::bpf_compile::VLAN_TPIDS;
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
/// The VLAN id is the frame's outermost tag (#208): the in-frame one at
/// bytes 12..16 (the capture re-inserts the tag the kernel stripped), else a
/// tag reported only in [`RxMetadata::vlan`](flowscope::RxMetadata) (the
/// kernel stripped it and it was not re-inserted; AF_XDP hardware metadata).
/// That is what the kernel prefilter's `vlan` blocks match too.
pub(crate) struct PacketFields {
    proto: L4Proto,
    src: SocketAddr,
    dst: SocketAddr,
    vlan: Option<u16>,
}

/// The VLAN id of `view`'s outermost tag: in the frame, else in the
/// metadata.
fn outer_vlan_id(view: &PacketView<'_>) -> Option<u16> {
    let f = view.frame;
    if let Some(tpid) = f.get(12..14) {
        let tpid = u16::from_be_bytes([tpid[0], tpid[1]]);
        if VLAN_TPIDS.contains(&tpid) {
            let tci = f.get(14..16)?;
            return Some(u16::from_be_bytes([tci[0], tci[1]]) & 0x0fff);
        }
    }
    view.rx_metadata.vlan.map(|t| t.vid())
}

impl PacketFields {
    /// Extract the 5-tuple from a frame. `None` for frames the extractor
    /// skips (ARP, malformed, non-IP) — those match no packet sub.
    pub(crate) fn extract(
        view: PacketView<'_>,
        extractor: &FiveTuple,
    ) -> Option<(FiveTupleKey, Self)> {
        let vlan = outer_vlan_id(&view);
        let ex = extractor.extract(view)?;
        let key = ex.key;
        Some((
            key,
            Self {
                proto: ex.l4.unwrap_or(key.proto),
                src: key.a,
                dst: key.b,
                vlan,
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
    fn vlan_id(&self) -> Option<u16> {
        self.vlan
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

    /// `frame` with a VLAN tag (`tpid`, `tci`) inserted after the MACs.
    fn tag(frame: &[u8], tpid: u16, tci: u16) -> Vec<u8> {
        let mut f = frame[..12].to_vec();
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&tci.to_be_bytes());
        f.extend_from_slice(&frame[12..]);
        f
    }

    /// #208: a `vlan 100` packet sub matches a frame tagged 100 — in the
    /// frame (re-inserted / offline) or only in the metadata — and nothing
    /// else. It used to evaluate to `false` on every frame.
    #[test]
    fn vlan_sub_matches_tagged_and_metadata_only_frames() {
        use flowscope::{RxMetadata, VlanProto, VlanTag};
        let sub = Predicate::Atom(Atom::VlanId(100));
        let ex = packet_field_extractor();
        let eval = |view: PacketView<'_>| {
            let (_k, fields) = PacketFields::extract(view, &ex).expect("udp frame extracts");
            sub.eval(&fields)
        };
        let ts = flowscope::Timestamp::new(0, 0);
        let plain = udp_frame(54321, 53);

        for tpid in VLAN_TPIDS {
            let f = tag(&plain, tpid, 0x2000 | 100); // PCP bits set
            assert!(eval(PacketView::new(&f, ts)), "in-frame {tpid:#06x}");
        }
        let other = tag(&plain, 0x8100, 101);
        assert!(!eval(PacketView::new(&other, ts)));
        assert!(!eval(PacketView::new(&plain, ts)), "untagged");

        let mut meta = RxMetadata::default();
        meta.vlan = Some(VlanTag::new(100, VlanProto::Dot1Q));
        assert!(
            eval(PacketView::new(&plain, ts).with_rx_metadata(meta)),
            "tag only in the metadata"
        );
        // QinQ in the frame: the outermost tag is the VLAN.
        let qinq = tag(&tag(&plain, 0x8100, 200), 0x88a8, 100);
        assert!(eval(PacketView::new(&qinq, ts)), "outer 802.1ad tag 100");
        let inner_100 = tag(&tag(&plain, 0x8100, 100), 0x88a8, 300);
        assert!(
            !eval(PacketView::new(&inner_100, ts)),
            "inner tag is not the VLAN"
        );
    }
}
