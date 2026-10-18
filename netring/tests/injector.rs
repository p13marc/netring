//! Integration tests for packet injection.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::{CaptureBuilder, Injector};
use std::time::{Duration, Instant};

/// Build a broadcast Ethernet frame with an experimental EtherType and
/// `marker` as payload.
fn marked_frame(marker: &[u8], seq: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&[0xff; 6]); // dst: broadcast
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src: locally administered
    f.extend_from_slice(&0x88b5u16.to_be_bytes()); // IEEE local experimental
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(marker);
    f.resize(f.len().max(60), 0);
    f
}

/// Count captured frames carrying `marker` until `want` are seen or the
/// deadline passes.
fn count_marked(rx: &mut netring::Capture, marker: &[u8], want: usize) -> usize {
    let mut found = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && found < want {
        if let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100)).unwrap() {
            for pkt in &batch {
                if pkt.data().windows(marker.len()).any(|w| w == marker) {
                    found += 1;
                }
            }
        }
    }
    found
}

/// Frames queued with `send()` + `flush()` must actually leave the socket:
/// a second AF_PACKET socket on `lo` sees them. (The other tests here only
/// check the injector's own bookkeeping, which a TX ring the kernel never
/// reads would satisfy just as well.)
#[test]
fn injected_frames_are_transmitted() {
    let marker = format!("netring_tx_{}", helpers::unique_port());
    let mut rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");
    let mut tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build injector");

    const N: u16 = 8;
    for seq in 0..N {
        let frame = marked_frame(marker.as_bytes(), seq);
        let mut slot = tx.allocate(frame.len()).expect("allocate slot");
        slot.data_mut()[..frame.len()].copy_from_slice(&frame);
        slot.set_len(frame.len());
        slot.send();
    }
    assert_eq!(tx.flush().expect("flush"), N as usize);
    tx.wait_drained(Duration::from_secs(2))
        .expect("kernel never reclaimed the TX slots");
    assert_eq!(tx.rejected_slots(), 0, "kernel rejected TX frames");
    assert_eq!(tx.available_slots(), tx.frame_count());

    let found = count_marked(&mut rx, marker.as_bytes(), N as usize);
    assert!(
        found >= N as usize,
        "captured {found} of {N} injected frames"
    );
}

/// A frame size that does not divide the ring's block size (here one
/// 3008-byte frame per 4096-byte block) still transmits every frame: the
/// kernel lays frames out per block, not back to back.
#[test]
fn injected_frames_with_an_odd_frame_size_are_transmitted() {
    let marker = format!("netring_txodd_{}", helpers::unique_port());
    let mut rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");
    let mut tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .frame_size(3008)
        .frame_count(8)
        .build()
        .expect("build injector");

    const N: u16 = 8;
    for seq in 0..N {
        let frame = marked_frame(marker.as_bytes(), seq);
        let mut slot = tx.allocate(frame.len()).expect("allocate slot");
        slot.data_mut()[..frame.len()].copy_from_slice(&frame);
        slot.set_len(frame.len());
        slot.send();
    }
    tx.flush().expect("flush");
    tx.wait_drained(Duration::from_secs(2))
        .expect("kernel never reclaimed the TX slots");

    // lo shows each frame twice (outgoing + incoming).
    let found = count_marked(&mut rx, marker.as_bytes(), 2 * N as usize);
    assert_eq!(
        found,
        2 * N as usize,
        "captured {found} of {N} injected frames, twice each"
    );
}

/// A frame filling the whole advertised capacity is transmitted intact.
#[test]
fn injected_frame_at_full_capacity_is_transmitted() {
    let marker = format!("netring_txcap_{}", helpers::unique_port());
    let mut rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");
    let mut tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build injector");

    let cap = tx.frame_capacity();
    let mut frame = marked_frame(marker.as_bytes(), 0);
    frame.resize(cap, 0xa5);
    let mut slot = tx.allocate(cap).expect("allocate full-capacity slot");
    slot.data_mut().copy_from_slice(&frame);
    slot.set_len(cap);
    slot.send();
    tx.flush().expect("flush");
    tx.wait_drained(Duration::from_secs(2))
        .expect("kernel never reclaimed the TX slot");
    assert_eq!(tx.rejected_slots(), 0, "kernel rejected the frame");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut got = None;
    while got.is_none() && Instant::now() < deadline {
        if let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100)).unwrap() {
            for pkt in &batch {
                let d = pkt.data();
                if d.windows(marker.len()).any(|w| w == marker.as_bytes()) {
                    got = Some(d.to_vec());
                    break;
                }
            }
        }
    }
    let got = got.expect("full-capacity frame not captured");
    assert_eq!(got.len(), cap, "captured length");
    assert_eq!(got, frame, "captured bytes differ from the injected frame");
}

#[test]
fn inject_allocate_send_flush() {
    let mut tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build injector");

    for i in 0u16..10 {
        let mut slot = tx.allocate(64).expect("allocate slot");
        let buf = slot.data_mut();
        buf[0..6].copy_from_slice(&[0xff; 6]); // broadcast
        buf[6..12].copy_from_slice(&[0x00; 6]); // src
        buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        buf[14..16].copy_from_slice(&i.to_be_bytes());
        slot.set_len(64);
        slot.send();
    }

    let flushed = tx.flush().expect("flush");
    assert_eq!(flushed, 10);
}

#[test]
fn inject_drop_without_send() {
    let mut tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build injector");

    // Allocate but don't send — should be discarded on drop
    {
        let mut slot = tx.allocate(64).expect("allocate slot");
        slot.data_mut()[0..6].copy_from_slice(&[0xff; 6]);
        slot.set_len(64);
        // drop without send()
    }

    // Flush should report 0 pending
    let flushed = tx.flush().expect("flush");
    assert_eq!(flushed, 0);
}

/// An injector has no RX ring, so it must not receive either: a socket
/// bound to `ETH_P_ALL` gets a copy of every packet on the interface
/// queued on its receive queue (until `rcvbuf` fills, then a drop per
/// packet) that nothing ever reads.
#[test]
fn injector_does_not_queue_received_traffic() {
    use std::os::fd::AsRawFd;

    let tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build injector");
    helpers::send_udp_to_loopback(helpers::unique_port(), b"netring_tx_rx", 16);
    std::thread::sleep(Duration::from_millis(50));

    let mut queued: libc::c_int = 0;
    // SAFETY: SIOCINQ (= FIONREAD) writes one int, the length of the
    // head of the receive queue, into `queued`.
    let rc = unsafe { libc::ioctl(tx.as_raw_fd(), libc::FIONREAD, &mut queued) };
    assert_eq!(rc, 0, "SIOCINQ: {}", std::io::Error::last_os_error());
    assert_eq!(queued, 0, "the TX socket queued received packets");
}

/// CPU time the calling thread has used.
fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer for the call.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Queue `frame` (allocate + send, no kick).
fn queue(tx: &mut Injector, frame: &[u8]) {
    let mut slot = tx.allocate(frame.len()).expect("a free slot");
    slot.data_mut()[..frame.len()].copy_from_slice(frame);
    slot.set_len(frame.len());
    slot.send();
}

/// #226: `Injector::wait_drained` must sleep, not spin, while frames are
/// pending. poll(2) on a TX-ring packet socket reports POLLOUT whenever its
/// write memory is below half `sk_sndbuf` (datagram_poll()), whatever the
/// ring holds, and POLLERR while TX timestamps sit unread in its error
/// queue — so the poll returned at once, every time, and the wait burnt a
/// core until its timeout. (A queued, never-kicked frame can't drain:
/// the wait times out, which is the point here.)
#[test]
fn wait_drained_does_not_spin() {
    let frame = marked_frame(b"netring-wait-drained", 0);
    for timestamps in [false, true] {
        let mut tx = match Injector::builder()
            .interface("lo")
            .frame_count(8)
            .tx_timestamps(timestamps)
            .build()
        {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("skip (needs CAP_NET_RAW): {e}");
                return;
            }
        };
        if timestamps {
            // Transmit a few, so egress timestamps wait, unread, in the
            // socket's error queue.
            for _ in 0..4 {
                queue(&mut tx, &frame);
            }
            tx.flush().unwrap();
            tx.wait_drained(Duration::from_secs(2)).unwrap();
        }
        queue(&mut tx, &frame);
        let (cpu, start) = (thread_cpu(), Instant::now());
        let err = tx
            .wait_drained(Duration::from_millis(300))
            .expect_err("a never-kicked frame never drains");
        let (cpu, wall) = (thread_cpu() - cpu, start.elapsed());
        assert!(
            matches!(&err, netring::Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "{err:?}"
        );
        assert!(
            wall >= Duration::from_millis(300),
            "returned early: {wall:?}"
        );
        assert!(
            cpu < Duration::from_millis(100),
            "timestamps={timestamps}: {cpu:?} of CPU in a {wall:?} wait"
        );
    }
}

/// Review: one frame the kernel refuses (here longer than the device's MTU
/// allows) stopped the kick with `EMSGSIZE` and left the kernel's TX
/// position on that slot, so every frame queued after it stayed queued.
/// Injectors now let the kernel drop a refused frame (`PACKET_LOSS`) and
/// go on; `drop_rejected(false)` keeps the strict behaviour.
#[test]
fn a_refused_frame_does_not_block_the_ring() {
    let Some(v) = helpers::VethPair::create("nrtxrej0", "nrtxrej1") else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let marker = format!("netring_tx_rejected_{}", helpers::unique_port());
    let mut sink = netring::CaptureBuilder::default()
        .interface(&v.b)
        .block_timeout_ms(10)
        .build()
        .expect("capture on the peer");
    let frame = |len: usize, seq: u8| {
        let mut f = vec![0xffu8; 6];
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x04]);
        f.extend_from_slice(&0x88b5u16.to_be_bytes());
        f.push(seq);
        f.extend_from_slice(marker.as_bytes());
        f.resize(len, 0);
        f
    };
    let mut tx = netring::Injector::builder()
        .interface(&v.a)
        .frame_count(8)
        .build()
        .expect("injector");
    // 1600 bytes on a 1500-byte MTU, then three ordinary frames.
    for (len, seq) in [(1600, 0u8), (100, 1), (100, 2), (100, 3)] {
        let f = frame(len, seq);
        let mut slot = tx.allocate(f.len()).expect("allocate");
        slot.data_mut()[..f.len()].copy_from_slice(&f);
        slot.set_len(f.len());
        slot.send();
    }
    tx.flush()
        .expect("a refused frame is dropped, not an error");
    tx.wait_drained(Duration::from_secs(2))
        .expect("nothing left queued");
    let mut seen = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline && seen < 3 {
        if let Some(batch) = sink.next_batch_blocking(Duration::from_millis(50)).unwrap() {
            seen += batch
                .iter()
                .filter(|p| {
                    p.data()
                        .windows(marker.len())
                        .any(|w| w == marker.as_bytes())
                })
                .count();
        }
    }
    assert_eq!(seen, 3, "the frames queued after the refused one");

    // Strict mode: the kick reports the refusal.
    let mut strict = netring::Injector::builder()
        .interface(&v.a)
        .frame_count(8)
        .drop_rejected(false)
        .build()
        .expect("strict injector");
    let f = frame(1600, 9);
    let mut slot = strict.allocate(f.len()).expect("allocate");
    slot.data_mut()[..f.len()].copy_from_slice(&f);
    slot.set_len(f.len());
    slot.send();
    let err = strict.flush().expect_err("EMSGSIZE");
    assert!(
        matches!(&err, netring::Error::Io(e) if e.raw_os_error() == Some(libc::EMSGSIZE)),
        "{err}"
    );
    assert_eq!(strict.rejected_slots(), 1);
}

/// `sh -c cmd`, true on success.
fn sh(cmd: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", cmd])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Queue one `len`-byte frame and kick it, blocking: `Ok` when the kernel
/// took it.
fn send_one(tx: &mut Injector, len: usize) -> Result<usize, netring::Error> {
    let mut f = vec![0u8; len];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    let mut slot = tx.allocate(len).expect("allocate");
    slot.data_mut()[..len].copy_from_slice(&f);
    slot.set_len(len);
    slot.send();
    tx.flush()
}

/// Review r5: a device stacked on a VLAN without VLAN TX offload (a
/// macvlan on a VLAN on a dummy) inherits the VLAN's 18-byte header
/// length, so the kernel takes `mtu + 18`; `max_frame_len` said
/// `mtu + 14` (and the bridge dropped what lay between). Whether the
/// header is 18 or 14 bytes depends on the lower device's VLAN offload,
/// so it's the kernel's to judge: `max_frame_len` is `None` there, and a
/// 1518-byte frame reaches the kernel, which takes it or refuses it
/// itself — never netring. A plain device keeps its exact limit.
#[test]
fn max_frame_len_is_none_on_a_device_stacked_on_a_vlan() {
    // Below the VLAN: a dummy (no VLAN TX offload: the VLAN's header is
    // 18 bytes), then a veth (offload: 14). The test passes either way the
    // kernel goes; the two lower devices make it go both ways here.
    for (lower, create) in [
        ("nrr5d0", "ip link add nrr5d0 type dummy"),
        ("nrr5v0", "ip link add nrr5v0 type veth peer name nrr5v1"),
    ] {
        stacked_on_a_vlan(lower, create);
    }
}

/// The macvlan-on-a-VLAN-on-`lower` case of
/// [`max_frame_len_is_none_on_a_device_stacked_on_a_vlan`].
fn stacked_on_a_vlan(lower: &str, create: &str) {
    let _ = sh(&format!("ip link del {lower}"));
    let (vlan_dev, mv) = (format!("{lower}.7"), format!("{lower}m"));
    if !sh(&format!(
        "{create} && ip link set {lower} up \
         && ip link add link {lower} name {vlan_dev} type vlan id 7 && ip link set {vlan_dev} up \
         && ip link add link {vlan_dev} name {mv} type macvlan mode bridge && ip link set {mv} up"
    )) {
        let _ = sh(&format!("ip link del {lower}"));
        eprintln!("skip: needs CAP_NET_ADMIN and the 8021q / macvlan modules");
        return;
    }
    let build = |iface: &str| {
        Injector::builder()
            .interface(iface)
            .frame_count(4)
            .drop_rejected(false)
            .build()
            .expect("injector")
    };
    let mut macvlan = build(&mv);
    let mfl = macvlan.max_frame_len().unwrap();
    let took = send_one(&mut macvlan, 1518);
    let rejected = macvlan.rejected_slots();
    let vlan = build(&vlan_dev).max_frame_len().unwrap();
    let plain = build(lower).max_frame_len().unwrap();
    let _ = sh(&format!("ip link del {lower}"));
    // The frame reached the kernel, which decided: sent (an 18-byte header:
    // no VLAN TX offload below), or refused with EMSGSIZE and its slot
    // left WRONG_FORMAT (a 14-byte header). Never netring.
    match &took {
        Ok(_) => assert_eq!(rejected, 0, "sent: nothing refused"),
        Err(netring::Error::Io(e)) if e.raw_os_error() == Some(libc::EMSGSIZE) => {
            assert_eq!(rejected, 1, "refused by the kernel, which marked the slot");
        }
        Err(e) => panic!("the kernel neither took nor refused the frame: {e}"),
    }
    eprintln!("1518 bytes on a macvlan over a VLAN over {lower}: {took:?}");
    assert_eq!(mfl, None, "a macvlan over a VLAN is the kernel's to judge");
    assert_eq!(vlan, None, "so is the VLAN");
    assert_eq!(plain, Some(1514), "{lower} has the plain Ethernet limit");
}

/// Review r5: the VLAN check read `/proc/net/vlan` through `/proc/self`
/// — the namespace of the process's main thread, not the socket's — so an
/// injector built inside `NetNs::run_in` on a VLAN there was taken for
/// plain Ethernet. The device is looked up where the socket was opened.
#[test]
fn max_frame_len_looks_at_the_sockets_namespace() {
    let _ = sh("ip netns del nrr5in");
    if !sh(
        "ip netns add nrr5in && ip -n nrr5in link add nrr5e0 type dummy \
         && ip -n nrr5in link set nrr5e0 up \
         && ip -n nrr5in link add link nrr5e0 name nrr5e0.9 type vlan id 9 \
         && ip -n nrr5in link set nrr5e0.9 up",
    ) {
        let _ = sh("ip netns del nrr5in");
        eprintln!("skip: needs CAP_SYS_ADMIN / CAP_NET_ADMIN and 8021q");
        return;
    }
    let ns = netring::netns::NetNs::from_name("nrr5in").expect("netns");
    let res = ns.run_in(|| {
        let mfl = |iface: &str| {
            Injector::builder()
                .interface(iface)
                .frame_count(4)
                .build()
                .and_then(|tx| tx.max_frame_len())
        };
        (mfl("nrr5e0.9"), mfl("nrr5e0"))
    });
    let _ = sh("ip netns del nrr5in");
    let (vlan, plain) = res.expect("run_in");
    assert_eq!(vlan.unwrap(), None, "a VLAN in the socket's namespace");
    assert_eq!(plain.unwrap(), Some(1514));
}
