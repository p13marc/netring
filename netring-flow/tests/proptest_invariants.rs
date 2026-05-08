//! Property-based tests for tracker invariants and parser robustness.
//!
//! Run with:
//!     cargo test -p netring-flow --test proptest_invariants
//!
//! Each property runs `proptest`'s default 256 cases. To increase
//! coverage:
//!     PROPTEST_CASES=10000 cargo test -p netring-flow --test proptest_invariants

use proptest::prelude::*;

use netring_flow::extract::FiveTuple;
use netring_flow::extract::parse::test_frames;
use netring_flow::{
    FlowEvent, FlowSide, FlowState, FlowTracker, FlowTrackerConfig, L4Proto, Orientation,
    PacketView, TcpFlags, Timestamp,
};

// ── strategies ─────────────────────────────────────────────────────

prop_compose! {
    fn arb_ipv4_addr()(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255)
        -> [u8; 4] { [a, b, c, d] }
}

prop_compose! {
    fn arb_port()(p in 1u16..=65_535) -> u16 { p }
}

prop_compose! {
    fn arb_tcp_flags()(
        syn in any::<bool>(), ack in any::<bool>(),
        fin in any::<bool>(), rst in any::<bool>(),
        psh in any::<bool>(),
    ) -> u8 {
        let mut f = 0;
        if fin { f |= 0x01; }
        if syn { f |= 0x02; }
        if rst { f |= 0x04; }
        if psh { f |= 0x08; }
        if ack { f |= 0x10; }
        f
    }
}

// ── property 1: bidirectional FiveTuple canonicalizes ──────────────

proptest! {
    #[test]
    fn five_tuple_bidirectional_canonicalizes(
        a_ip in arb_ipv4_addr(),
        b_ip in arb_ipv4_addr(),
        a_port in arb_port(),
        b_port in arb_port(),
    ) {
        // Skip a == b (same endpoint both directions = degenerate)
        prop_assume!(a_ip != b_ip || a_port != b_port);

        use netring_flow::FlowExtractor;
        let extractor = FiveTuple::bidirectional();

        let fwd = test_frames::ipv4_tcp(
            [0; 6], [0; 6],
            a_ip, b_ip,
            a_port, b_port,
            0, 0, 0x02, b"",
        );
        let rev = test_frames::ipv4_tcp(
            [0; 6], [0; 6],
            b_ip, a_ip,
            b_port, a_port,
            0, 0, 0x12, b"",
        );

        let e_fwd = extractor.extract(PacketView::new(&fwd, Timestamp::default())).unwrap();
        let e_rev = extractor.extract(PacketView::new(&rev, Timestamp::default())).unwrap();

        prop_assert_eq!(e_fwd.key, e_rev.key, "canonical keys must match");
        prop_assert_ne!(e_fwd.orientation, e_rev.orientation, "orientations must differ");
    }
}

// ── property 2: TCP state never panics ─────────────────────────────

proptest! {
    #[test]
    fn tcp_state_machine_never_panics(
        seq in proptest::collection::vec(
            (any::<bool>(), arb_tcp_flags()),
            0..32,
        ),
    ) {
        let mut state = FlowState::Active;
        for (initiator, flags_byte) in seq {
            let mut flags = TcpFlags::empty();
            if flags_byte & 0x01 != 0 { flags |= TcpFlags::FIN; }
            if flags_byte & 0x02 != 0 { flags |= TcpFlags::SYN; }
            if flags_byte & 0x04 != 0 { flags |= TcpFlags::RST; }
            if flags_byte & 0x10 != 0 { flags |= TcpFlags::ACK; }
            let side = if initiator { FlowSide::Initiator } else { FlowSide::Responder };
            let new = netring_flow::tcp_state::transition(state, flags, side).state;
            // The new state must be one of the known variants — no panic.
            // Implicit via the match — if the function returned an invalid
            // state, debug-mode would catch it.
            state = new;
        }
        // Property: any sequence reduces to a known state.
        let _ = state;
    }
}

// ── property 3: tracker invariants ─────────────────────────────────

proptest! {
    #[test]
    fn tracker_flow_count_never_exceeds_max(
        n_flows in 1u16..200u16,
        max_flows in 5usize..32usize,
    ) {
        let cfg = FlowTrackerConfig {
            max_flows,
            ..FlowTrackerConfig::default()
        };
        let mut t = FlowTracker::<FiveTuple>::with_config(
            FiveTuple::bidirectional(),
            cfg,
        );
        for i in 0..n_flows {
            // Distinct flows by varying source port.
            let f = test_frames::ipv4_udp(
                [10, 0, 0, 1], [10, 0, 0, 2],
                1024 + i, 80, b"x",
            );
            t.track(PacketView::new(&f, Timestamp::default()));
        }
        prop_assert!(
            t.flow_count() <= max_flows,
            "flow_count={} exceeds max_flows={}",
            t.flow_count(), max_flows
        );
    }

    #[test]
    fn tracker_stats_balance(
        n_flows in 1u16..50u16,
        max_flows in 5usize..32usize,
    ) {
        // After processing N distinct flows: created = ended + active
        // (where ended includes both Fin/Rst/IdleTimeout/Evicted).
        let cfg = FlowTrackerConfig { max_flows, ..FlowTrackerConfig::default() };
        let mut t = FlowTracker::<FiveTuple>::with_config(
            FiveTuple::bidirectional(),
            cfg,
        );
        for i in 0..n_flows {
            let f = test_frames::ipv4_udp(
                [10, 0, 0, 1], [10, 0, 0, 2],
                1024 + i, 80, b"x",
            );
            t.track(PacketView::new(&f, Timestamp::default()));
        }
        let s = t.stats();
        prop_assert_eq!(
            s.flows_created as usize,
            s.flows_ended as usize + t.flow_count(),
            "balance: created={} != ended={} + active={}",
            s.flows_created, s.flows_ended, t.flow_count(),
        );
    }
}

// ── property 4: extractor never panics on arbitrary frame bytes ────

proptest! {
    #[test]
    fn five_tuple_doesnt_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        use netring_flow::FlowExtractor;
        let extractor = FiveTuple::bidirectional();
        // Should never panic, regardless of input.
        let _ = extractor.extract(PacketView::new(&bytes, Timestamp::default()));
    }

    #[test]
    fn strip_vlan_doesnt_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        use netring_flow::FlowExtractor;
        use netring_flow::extract::StripVlan;
        let extractor = StripVlan(FiveTuple::bidirectional());
        let _ = extractor.extract(PacketView::new(&bytes, Timestamp::default()));
    }

    #[test]
    fn strip_mpls_doesnt_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        use netring_flow::FlowExtractor;
        use netring_flow::extract::StripMpls;
        let extractor = StripMpls(FiveTuple::bidirectional());
        let _ = extractor.extract(PacketView::new(&bytes, Timestamp::default()));
    }

    #[test]
    fn inner_vxlan_doesnt_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        use netring_flow::FlowExtractor;
        use netring_flow::extract::InnerVxlan;
        let extractor = InnerVxlan::new(FiveTuple::bidirectional());
        let _ = extractor.extract(PacketView::new(&bytes, Timestamp::default()));
    }

    #[test]
    fn inner_gtp_u_doesnt_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        use netring_flow::FlowExtractor;
        use netring_flow::extract::InnerGtpU;
        let extractor = InnerGtpU::new(FiveTuple::bidirectional());
        let _ = extractor.extract(PacketView::new(&bytes, Timestamp::default()));
    }
}

// ── property 5: Established always implies Started preceded ────────

proptest! {
    #[test]
    fn established_always_after_started(
        n_packets in 1u8..16,
    ) {
        // A 3WHS sequence followed by N data packets should have
        // exactly one Established event; Started must come before
        // it in the event order.
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let syn = test_frames::ipv4_tcp([0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, 0, 0x02, b"");
        let synack = test_frames::ipv4_tcp([0; 6], [0; 6], [10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 200, 101, 0x12, b"");
        let ack = test_frames::ipv4_tcp([0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 101, 201, 0x10, b"");

        let mut all = Vec::new();
        all.extend(t.track(PacketView::new(&syn, Timestamp::new(0, 0))));
        all.extend(t.track(PacketView::new(&synack, Timestamp::new(0, 0))));
        all.extend(t.track(PacketView::new(&ack, Timestamp::new(0, 0))));

        // Optional more data packets.
        for i in 0..n_packets {
            let data = test_frames::ipv4_tcp(
                [0; 6], [0; 6],
                [10, 0, 0, 1], [10, 0, 0, 2],
                1234, 80,
                101 + i as u32, 201,
                0x18,
                b"x",
            );
            all.extend(t.track(PacketView::new(&data, Timestamp::new(0, 0))));
        }

        let started_pos = all.iter().position(|e| matches!(e, FlowEvent::Started { .. }));
        let established_pos = all.iter().position(|e| matches!(e, FlowEvent::Established { .. }));

        prop_assert!(started_pos.is_some(), "must see Started");
        prop_assert!(established_pos.is_some(), "must see Established");
        prop_assert!(started_pos < established_pos, "Started must precede Established");
    }
}

// Suppress unused warnings on Orientation since some properties
// don't use it directly.
#[allow(dead_code)]
fn _unused_orientation_keepalive(_: Orientation, _: L4Proto) {}
