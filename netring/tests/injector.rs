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
