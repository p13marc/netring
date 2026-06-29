//! 0.22 R2 — the flat (non-parameterised) `FlowPacket` event.
//!
//! Asserts the type shape: `FlowPacket` carries `proto` and is a
//! single `Event` (no `<P>`). The dispatch-level "one handler sees
//! all L4" behaviour is covered by `typed_flow_packet_event.rs`.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use flowscope::{FlowSide, L4Proto, Timestamp};
use netring::protocol::event_typed::{Event, FlowPacket};

fn key(proto: L4Proto) -> flowscope::extract::FiveTupleKey {
    flowscope::extract::FiveTupleKey::new(
        proto,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    )
}

#[test]
fn flow_packet_is_flat_and_carries_proto() {
    fn _is_event<E: Event>() {}
    _is_event::<FlowPacket>(); // single, non-generic Event

    let pkt = FlowPacket::new(
        L4Proto::Udp,
        key(L4Proto::Udp),
        FlowSide::Responder,
        128,
        None,
        Timestamp::new(0, 0),
    );
    assert_eq!(pkt.proto, L4Proto::Udp);
    assert_eq!(pkt.len, 128);
    assert_eq!(pkt.side, FlowSide::Responder);
    // Debug + Clone derived (0.22 R2).
    let _ = format!("{:?}", pkt.clone());
}
