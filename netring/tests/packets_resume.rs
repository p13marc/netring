//! #211: a block a `Packets` loop has only partly read survives the loop.
//!
//! The kernel hands packets over a block at a time; before 0.32 dropping (or
//! stopping) a `Packets` released the whole current block, so every packet
//! of it the loop had not reached yet was lost. The read position now lives
//! in the `Capture`: the next `packets()` loop or `next_batch()` continues
//! where the previous one stopped.
//!
//! Needs `CAP_NET_RAW`; skips without it. Timing-sensitive (one ring block
//! must hold a burst): on a busy host run it in a fresh network namespace.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::net::UdpSocket;
use std::time::Duration;

use netring::{BpfFilter, Capture, Error};

const MARKER: &[u8; 8] = b"NRRESUME";
/// Ethernet + IPv4 + UDP headers in front of the payload.
const PAYLOAD_OFF: usize = 14 + 20 + 8;
const SYNC: u32 = u32::MAX;

fn private_port(slot: u16) -> u16 {
    45_000 + (std::process::id() % 4_000) as u16 * 4 + slot
}

/// A capture of the UDP datagrams to `port` on `lo`, each seen once, with a
/// 1 MiB block retired by a 200 ms timer — a burst of 50 fits in one block.
fn capture(port: u16) -> Option<Capture> {
    let built = Capture::builder()
        .interface(helpers::LOOPBACK)
        .ignore_outgoing(true)
        .block_size(1 << 20)
        .block_count(4)
        .block_timeout_ms(200)
        .poll_timeout(Duration::from_millis(50))
        .bpf_filter(
            BpfFilter::builder()
                .udp()
                .dst_port(port)
                .build()
                .expect("filter"),
        )
        .build();
    match built {
        Ok(cap) => Some(cap),
        Err(Error::PermissionDenied) => {
            eprintln!("skipping: needs CAP_NET_RAW");
            None
        }
        Err(e) => panic!("build capture: {e}"),
    }
}

fn send(port: u16, seqs: impl IntoIterator<Item = u32>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for seq in seqs {
        let mut payload = MARKER.to_vec();
        payload.extend_from_slice(&seq.to_be_bytes());
        sock.send_to(&payload, ("127.0.0.1", port))
            .expect("send_to");
    }
}

/// The sequence number of one of our datagrams.
fn seq_of(frame: &[u8]) -> Option<u32> {
    let p = frame.get(PAYLOAD_OFF..PAYLOAD_OFF + 12)?;
    (p[..8] == MARKER[..]).then(|| u32::from_be_bytes(p[8..12].try_into().unwrap()))
}

/// Send a lone sync datagram and read up to it: the block that carried it
/// is retired by the block timer, which opens the next block with a fresh
/// 200 ms timer — so a burst sent right after lands in one block.
fn sync(cap: &mut Capture, port: u16) {
    send(port, [SYNC]);
    let mut pkts = cap.packets_for(Duration::from_secs(3));
    while let Some(pkt) = pkts.next_packet() {
        if seq_of(pkt.data()) == Some(SYNC) {
            return;
        }
    }
    panic!("sync datagram never arrived");
}

/// Up to `n` sequence numbers from a fresh `packets_for(timeout)` loop.
fn take(cap: &mut Capture, n: usize, timeout: Duration) -> Vec<u32> {
    let mut out = Vec::new();
    let mut pkts = cap.packets_for(timeout);
    while out.len() < n {
        let Some(pkt) = pkts.next_packet() else { break };
        out.extend(seq_of(pkt.data()));
    }
    out
}

#[test]
fn dropping_packets_mid_block_keeps_the_rest() {
    let port = private_port(0);
    let Some(mut cap) = capture(port) else {
        return;
    };
    sync(&mut cap, port);
    send(port, 0..50);

    // Take ten, then drop the loop with 40 of the block unread.
    assert_eq!(
        take(&mut cap, 10, Duration::from_secs(2)),
        (0..10).collect::<Vec<_>>()
    );

    // 0.31: the block was released with the loop — this saw nothing.
    let rest = take(&mut cap, 40, Duration::from_secs(2));
    assert_eq!(
        rest,
        (10..50).collect::<Vec<_>>(),
        "the unread packets, in order"
    );
}

#[test]
fn stop_mid_block_keeps_the_rest() {
    let port = private_port(1);
    let Some(mut cap) = capture(port) else {
        return;
    };
    let stop = cap.stop_handle().expect("stop handle");
    sync(&mut cap, port);
    send(port, 0..50);

    let mut seen = Vec::new();
    {
        let mut pkts = cap.packets_for(Duration::from_secs(2));
        while let Some(pkt) = pkts.next_packet() {
            seen.extend(seq_of(pkt.data()));
            if seen.len() == 10 {
                stop.stop();
            }
        }
        // A stopped loop yields nothing more…
        assert!(pkts.next_packet().is_none());
    }
    assert_eq!(seen, (0..10).collect::<Vec<_>>(), "stopped after ten");

    // …and after `clear_stop` the next loop resumes mid-block.
    cap.clear_stop();
    let rest = take(&mut cap, 40, Duration::from_secs(2));
    assert_eq!(rest, (10..50).collect::<Vec<_>>());
}

#[test]
fn next_batch_after_partial_packets() {
    let port = private_port(2);
    let Some(mut cap) = capture(port) else {
        return;
    };
    sync(&mut cap, port);
    send(port, 0..50);
    assert_eq!(
        take(&mut cap, 10, Duration::from_secs(2)),
        (0..10).collect::<Vec<_>>()
    );

    // The rest of the partly read block is ready at once, as a batch of
    // the 40 unread packets.
    let batch = cap
        .next_batch_blocking(Duration::from_secs(2))
        .expect("poll")
        .expect("the rest of the block");
    assert_eq!(batch.len(), 40);
    let seqs: Vec<u32> = batch.iter().filter_map(|p| seq_of(p.data())).collect();
    assert_eq!(seqs, (10..50).collect::<Vec<_>>());
    drop(batch);

    // Dropping the batch handed the block back: nothing is left.
    assert!(take(&mut cap, 1, Duration::from_millis(500)).is_empty());
}
