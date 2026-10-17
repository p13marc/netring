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

    let stats = bridge.stats().expect("stats");
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
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let bridge_thread = std::thread::spawn(move || {
        let mut bridge = Bridge::builder()
            .interface_a(&a)
            .interface_b(&b)
            .poll_timeout(Duration::from_millis(20))
            .build()
            .expect("build bridge");
        // Built = both RX sockets bound and receiving.
        ready_tx.send(()).expect("signal ready");
        bridge
            .run_iterations(100, |_pkt, _dir| BridgeAction::Forward)
            .expect("run_iterations");
    });
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("bridge never came up");

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

/// A broadcast frame with an experimental EtherType carrying `marker`.
fn marked_frame(marker: &[u8], seq: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x03]);
    frame.extend_from_slice(&0x88b5u16.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(marker);
    frame.resize(frame.len().max(60), 0);
    frame
}

/// Send `n` marked frames out of `iface` with one kick.
fn inject_marked(iface: &str, marker: &[u8], n: u16) {
    let mut tx = netring::Injector::builder()
        .interface(iface)
        .frame_count(usize::from(n).max(1))
        .build()
        .expect("injector");
    for seq in 0..n {
        let frame = marked_frame(marker, seq);
        let mut slot = tx.allocate(frame.len()).expect("allocate");
        slot.data_mut()[..frame.len()].copy_from_slice(&frame);
        slot.set_len(frame.len());
        slot.send();
    }
    tx.flush().expect("flush");
    tx.wait_drained(Duration::from_secs(2)).expect("drained");
}

/// Count frames carrying `marker` on `cap` until `window` passes.
fn count_marked(cap: &mut netring::Capture, marker: &[u8], window: Duration) -> usize {
    let mut found = 0;
    let deadline = std::time::Instant::now() + window;
    while std::time::Instant::now() < deadline {
        if let Some(batch) = cap.next_batch_blocking(Duration::from_millis(50)).unwrap() {
            found += batch
                .iter()
                .filter(|p| p.data().windows(marker.len()).any(|w| w == marker))
                .count();
        }
    }
    found
}

/// Two veth pairs `x` and `y` with `nrp` names unique to this process,
/// with IPv6 off so the only traffic on them is the test's own.
fn veth_pairs(tag: &str) -> Option<(VethPair, VethPair)> {
    let pid = std::process::id() % 1000;
    let x = VethPair::create(&format!("nrp{tag}{pid}x0"), &format!("nrp{tag}{pid}x1"))?;
    let y = VethPair::create(&format!("nrp{tag}{pid}y0"), &format!("nrp{tag}{pid}y1"))?;
    for name in [&x.a, &x.b, &y.a, &y.b] {
        let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "1");
    }
    Some((x, y))
}

/// More packets in one RX block than the TX ring has frames: every one is
/// forwarded (the TX ring is kicked when it fills), none counted ring-full.
#[test]
fn bridge_forwards_a_block_larger_than_the_tx_ring() {
    let Some((x, y)) = veth_pairs("f") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let marker = format!("netring_bridge_full_{}", helpers::unique_port());
    let mut sink = netring::CaptureBuilder::default()
        .interface(&y.a)
        .block_timeout_ms(10)
        .build()
        .expect("capture on y0");
    // One long-lived RX block on A, so all frames arrive in a single batch.
    let mut bridge = Bridge::builder()
        .interface_a(&x.b)
        .interface_b(&y.b)
        .a_block_timeout_ms(1_000)
        .poll_timeout(Duration::from_millis(50))
        .build()
        .expect("build bridge");
    let tx_frames = bridge.handles().1.frame_count();

    const N: u16 = 2_000;
    assert!(usize::from(N) > 4 * tx_frames);
    inject_marked(&x.a, marker.as_bytes(), N);
    bridge
        .run_iterations(40, |_pkt, _dir| BridgeAction::Forward)
        .expect("run_iterations");

    let stats = bridge.stats().expect("stats");
    assert_eq!(stats.a_to_b_dropped_ring_full, 0, "{stats}");
    let found = count_marked(&mut sink, marker.as_bytes(), Duration::from_millis(500));
    assert_eq!(
        found,
        usize::from(N),
        "y0 captured {found} of {N} bridged frames"
    );
}

/// Without qdisc bypass, the bridge's own transmissions pass the packet
/// taps on the egress interface, so its other RX socket sees them as
/// outgoing. Forwarding those back makes every frame ping-pong between the
/// two sides forever; one injected frame must arrive exactly once.
#[test]
fn bridge_does_not_forward_its_own_transmissions() {
    let Some((x, y)) = veth_pairs("l") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let marker = format!("netring_bridge_loop_{}", helpers::unique_port());
    let mut sink = netring::CaptureBuilder::default()
        .interface(&y.a)
        .block_timeout_ms(10)
        .build()
        .expect("capture on y0");
    let mut bridge = Bridge::builder()
        .interface_a(&x.b)
        .interface_b(&y.b)
        .qdisc_bypass(false)
        .a_block_timeout_ms(5)
        .b_block_timeout_ms(5)
        .poll_timeout(Duration::from_millis(20))
        .build()
        .expect("build bridge");

    inject_marked(&x.a, marker.as_bytes(), 1);
    bridge
        .run_iterations(20, |_pkt, _dir| BridgeAction::Forward)
        .expect("run_iterations");

    let found = count_marked(&mut sink, marker.as_bytes(), Duration::from_millis(300));
    assert_eq!(found, 1, "y0 received the one bridged frame {found} times");
}

/// A backlog on one side does not hold up the other: B's frame is served
/// after a bounded share of A's blocks, not after A's whole ring. (Under
/// sustained load on A, draining A until empty never ends.)
#[test]
fn bridge_serves_both_sides_under_a_backlog() {
    let Some((x, y)) = veth_pairs("s") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let a_marker = format!("netring_bridge_a_{}", helpers::unique_port());
    let b_marker = format!("netring_bridge_b_{}", helpers::unique_port());
    // Small blocks on A, so its backlog spans many of them.
    let mut bridge = Bridge::builder()
        .interface_a(&x.b)
        .interface_b(&y.b)
        .a_block_size(1 << 16)
        .a_block_count(64)
        .a_block_timeout_ms(5)
        .b_block_timeout_ms(5)
        .build()
        .expect("build bridge");

    const N: u16 = 3_000;
    inject_marked(&x.a, a_marker.as_bytes(), N);
    inject_marked(&y.a, b_marker.as_bytes(), 1);
    std::thread::sleep(Duration::from_millis(100)); // every block retired

    let has =
        |pkt: &netring::Packet<'_>, m: &str| pkt.data().windows(m.len()).any(|w| w == m.as_bytes());
    let (mut a_seen, mut a_before_b, mut b_seen) = (0usize, None, false);
    bridge
        .run_iterations(1, |pkt, dir| {
            if dir == BridgeDirection::AtoB && has(pkt, &a_marker) {
                a_seen += 1;
            }
            if dir == BridgeDirection::BtoA && has(pkt, &b_marker) {
                b_seen = true;
                a_before_b.get_or_insert(a_seen);
            }
            BridgeAction::Drop
        })
        .expect("run_iterations");

    assert!(b_seen, "B's frame was not served in the first iteration");
    let a_before_b = a_before_b.unwrap();
    assert!(
        a_before_b < usize::from(N),
        "B waited for all {a_before_b} of A's backlog"
    );
}

/// The async loop comes back for the part of a backlog one turn left
/// behind, although no new packet (no new epoll edge) arrives.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn bridge_async_resumes_a_backlog() {
    let Some((x, y)) = veth_pairs("q") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let marker = format!("netring_bridge_q_{}", helpers::unique_port());
    let mut bridge = Bridge::builder()
        .interface_a(&x.b)
        .interface_b(&y.b)
        .a_block_size(1 << 16)
        .a_block_count(64)
        .a_block_timeout_ms(5)
        .poll_timeout(Duration::from_millis(20))
        .build()
        .expect("build bridge");

    const N: u16 = 3_000;
    inject_marked(&x.a, marker.as_bytes(), N);
    tokio::time::sleep(Duration::from_millis(100)).await; // every block retired

    let mut seen = 0usize;
    bridge
        .run_iterations_async(20, |pkt, _dir| {
            if pkt
                .data()
                .windows(marker.len())
                .any(|w| w == marker.as_bytes())
            {
                seen += 1;
            }
            BridgeAction::Drop
        })
        .await
        .expect("run_iterations_async");
    assert_eq!(seen, usize::from(N), "the async bridge stopped mid-backlog");
}

/// #228: the async bridge does not wait for the device. It forwarded each
/// batch with a blocking kick (a flags-0 `sendto` on the TX ring, which
/// waits until every frame it handed over completes — tpacket_snd()
/// `need_wait`), so a device that holds frames, here side B's `plug`
/// qdisc with the bridge going through the qdisc (`qdisc_bypass(false)`),
/// stalled `run_iterations_async` inside the syscall: the loop, the
/// other direction and the runtime thread with it. It now kicks with
/// `MSG_DONTWAIT`.
#[cfg(feature = "tokio")]
#[test]
fn async_bridge_does_not_wait_for_a_device_that_holds_frames() {
    use helpers::PluggedDummy;
    use netring::Injector;
    use std::sync::mpsc;
    use std::time::Instant;

    let Some(x) = VethPair::create("nrtest_p0", "nrtest_p1") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let Some(plugged) = PluggedDummy::create_named("nrtest_plug") else {
        eprintln!("skipping: cannot create a plugged dummy (CAP_NET_ADMIN, sch_plug)");
        return;
    };

    let (a, b) = (x.b.clone(), plugged.0.clone());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let bridge_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            // Through the qdisc (the default bypasses it, and a direct
            // transmit never holds a frame): a bridge that shapes or
            // queues its traffic.
            let mut bridge = Bridge::builder()
                .interface_a(&a)
                .interface_b(&b)
                .qdisc_bypass(false)
                .poll_timeout(Duration::from_millis(20))
                .build()
                .expect("build bridge");
            ready_tx.send(()).expect("signal ready");
            let mut forwarded = 0u32;
            let result = bridge
                .run_iterations_async(60, |_pkt, dir| {
                    if dir == BridgeDirection::AtoB {
                        forwarded += 1;
                    }
                    BridgeAction::Forward
                })
                .await;
            let _ = done_tx.send((result.map_err(|e| e.to_string()), forwarded));
        });
    });
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("bridge never came up");

    // Frames into side A (x1), forwarded out of side B, where the qdisc
    // holds them.
    let mut tx = Injector::open(&x.a).expect("injector on p0");
    for seq in 0..8u16 {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        frame.extend_from_slice(&0x88b5u16.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.resize(60, 0);
        let mut slot = tx.allocate(frame.len()).expect("allocate");
        slot.data_mut()[..frame.len()].copy_from_slice(&frame);
        slot.set_len(frame.len());
        slot.send();
    }
    tx.flush().expect("flush");

    // 60 iterations of at most 20 ms each: well under 10 s unless a kick
    // blocks.
    let start = Instant::now();
    let outcome = done_rx.recv_timeout(Duration::from_secs(10));
    let elapsed = start.elapsed();
    // Deleting the plugged device releases its frames, so a blocked kick
    // returns and the thread can be joined either way.
    drop(plugged);
    bridge_thread.join().expect("bridge thread");
    let (result, forwarded) = outcome.unwrap_or_else(|_| {
        panic!("run_iterations_async stalled for {elapsed:?} on a device holding frames")
    });
    result.expect("run_iterations_async");
    assert!(forwarded > 0, "the bridge forwarded nothing A→B");
}
