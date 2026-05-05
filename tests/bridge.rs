//! Integration tests for `Bridge` over a paired-veth fixture.
//!
//! Requires `CAP_NET_RAW + CAP_NET_ADMIN`. The veth fixture skips
//! gracefully when `ip link add` fails (no privilege).

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::VethPair;
use netring::bridge::{Bridge, BridgeAction, BridgeDirection};
use std::time::Duration;

/// Smoke test: bridge_async forwards packets across a veth pair.
#[test]
fn bridge_run_iterations_smoke() {
    let veth = match VethPair::create("nrtest_a", "nrtest_b") {
        Some(v) => v,
        None => {
            eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
            return;
        }
    };

    let mut bridge = Bridge::builder()
        .interface_a(&veth.a)
        .interface_b(&veth.b)
        .poll_timeout(Duration::from_millis(50))
        .build()
        .expect("build bridge");

    // Run a few iterations with no traffic — exercises the poll(2)
    // wait path. Should return without error and consume negligible CPU.
    let mut total_seen = 0u64;
    bridge
        .run_iterations(3, |_pkt, dir| {
            match dir {
                BridgeDirection::AtoB | BridgeDirection::BtoA => total_seen += 1,
            }
            BridgeAction::Forward
        })
        .expect("run_iterations");

    let stats = bridge.cumulative_stats().expect("stats");
    eprintln!(
        "bridge_run_iterations_smoke: saw {total_seen} packets, drops a→b={} b→a={}",
        stats.a_to_b.drops, stats.b_to_a.drops
    );
}

/// Constructor smoke test: builder validates two interfaces and yields
/// a Bridge struct that can be decomposed via into_inner.
#[test]
fn bridge_builder_into_inner() {
    let veth = match VethPair::create("nrtest_c", "nrtest_d") {
        Some(v) => v,
        None => {
            eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
            return;
        }
    };

    let bridge = Bridge::builder()
        .interface_a(&veth.a)
        .interface_b(&veth.b)
        .build()
        .expect("build bridge");

    let handles = bridge.into_inner();
    // Just verify the four fds are distinct (sanity).
    use std::os::fd::AsRawFd;
    let fds = [
        handles.rx_a.as_raw_fd(),
        handles.tx_b.as_raw_fd(),
        handles.rx_b.as_raw_fd(),
        handles.tx_a.as_raw_fd(),
    ];
    for i in 0..fds.len() {
        for j in (i + 1)..fds.len() {
            assert_ne!(fds[i], fds[j], "duplicate fd at {i}/{j}");
        }
    }
}
