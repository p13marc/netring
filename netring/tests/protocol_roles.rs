//! 0.22 R1 — typed protocol roles. Compile-time assertions that the
//! `FlowProtocol` / `MessageProtocol` split admits exactly the valid
//! event/handler combinations and rejects the nonsensical ones.
//!
//! The *negative* cases (`on::<Tcp>`, `FlowStarted<Http>`) can't be
//! written here — they wouldn't compile. They're documented as
//! `compile_fail` doctests on the marker traits + asserted by
//! omission. This file pins the *positive* surface so a regression in
//! the trait impls (e.g. dropping `impl FlowProtocol for Icmp`) breaks
//! the build.

#![cfg(all(feature = "tokio", feature = "flow"))]

use netring::protocol::event_typed::{Event, FlowEnded, FlowEstablished, FlowStarted, FlowTick};
use netring::protocol::{FlowProtocol, MessageProtocol};
use netring::protocol::builtin::{Tcp, Udp};

fn assert_event<E: Event>() {}
fn assert_flow_protocol<P: FlowProtocol>() {}
fn assert_message_protocol<P: MessageProtocol>() {}

#[test]
fn tcp_udp_are_flow_protocols_with_lifecycle_events() {
    assert_flow_protocol::<Tcp>();
    assert_flow_protocol::<Udp>();
    // Lifecycle events exist for flow protocols.
    assert_event::<FlowStarted<Tcp>>();
    assert_event::<FlowEstablished<Tcp>>();
    assert_event::<FlowEnded<Tcp>>();
    assert_event::<FlowTick<Tcp>>();
    assert_event::<FlowStarted<Udp>>();
    assert_event::<FlowEnded<Udp>>();
}

#[cfg(feature = "icmp")]
#[test]
fn icmp_is_both_flow_and_message_protocol() {
    use netring::protocol::builtin::Icmp;
    // ICMP is dual-role: tracked as a flow AND delivers messages.
    assert_flow_protocol::<Icmp>();
    assert_message_protocol::<Icmp>();
    assert_event::<FlowStarted<Icmp>>(); // flow lifecycle
    assert_event::<Icmp>(); // raw IcmpMessage via on::<Icmp>
}

#[cfg(feature = "http")]
#[test]
fn http_is_message_only() {
    use netring::protocol::builtin::Http;
    assert_message_protocol::<Http>();
    // `on::<Http>` fires HttpMessage.
    assert_event::<Http>();
    // NOTE: `assert_event::<FlowStarted<Http>>()` would NOT compile —
    // Http is not a FlowProtocol. That's the R1 guarantee.
}

#[cfg(feature = "dns")]
#[test]
fn dns_is_message_only() {
    use netring::protocol::builtin::Dns;
    assert_message_protocol::<Dns>();
    assert_event::<Dns>();
}
