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

/// End-to-end forwarding: a frame injected on `x0` enters the bridge on `x1`
/// (side A), is re-sent out of `y1` (side B), and must be captured on `y0`.
/// Before #187 the bridge's TX rings never transmitted, so nothing arrived.
#[test]
fn bridge_forwards_frames_a_to_b() {
    use netring::{CaptureBuilder, Injector};
    use std::time::Instant;

    let Some(x) = VethPair::create("nrtest_x0", "nrtest_x1") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let Some(y) = VethPair::create("nrtest_y0", "nrtest_y1") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };

    let marker = format!("netring_bridge_{}", helpers::unique_port());
    let mut sink = CaptureBuilder::default()
        .interface(&y.a)
        .block_timeout_ms(10)
        .build()
        .expect("build capture on y0");

    let (a, b) = (x.b.clone(), y.b.clone());
    let bridge_thread = std::thread::spawn(move || {
        let mut bridge = Bridge::builder()
            .interface_a(&a)
            .interface_b(&b)
            .poll_timeout(Duration::from_millis(20))
            .build()
            .expect("build bridge");
        bridge
            .run_iterations(100, |_pkt, _dir| BridgeAction::Forward)
            .expect("run_iterations");
    });
    // Let the bridge open its sockets before traffic starts.
    std::thread::sleep(Duration::from_millis(200));

    let mut tx = Injector::open(&x.a).expect("injector on x0");
    const N: u16 = 4;
    for seq in 0..N {
        let mut frame = Vec::with_capacity(64);
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        frame.extend_from_slice(&0x88b5u16.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(marker.as_bytes());
        frame.resize(frame.len().max(60), 0);
        let mut slot = tx.allocate(frame.len()).expect("allocate");
        slot.data_mut()[..frame.len()].copy_from_slice(&frame);
        slot.set_len(frame.len());
        slot.send();
    }
    tx.flush().expect("flush");

    let mut found = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && found < N as usize {
        if let Some(batch) = sink
            .next_batch_blocking(Duration::from_millis(100))
            .unwrap()
        {
            for pkt in &batch {
                if pkt
                    .data()
                    .windows(marker.len())
                    .any(|w| w == marker.as_bytes())
                {
                    found += 1;
                }
            }
        }
    }
    bridge_thread.join().expect("bridge thread");
    assert!(
        found >= N as usize,
        "y0 captured {found} of {N} bridged frames"
    );
}
