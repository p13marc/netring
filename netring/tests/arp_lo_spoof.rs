//! Root-gated end-to-end ARP test on the loopback interface.
//!
//! Builds a real Monitor on `lo` with `.on_arp` + `.on_arp_anomaly`,
//! injects a crafted **gratuitous ARP reply** (sender_ip == target_ip,
//! target MAC ≠ sender MAC — the classic spoof pattern) as a raw L2 frame
//! via netring's own `Injector`, and asserts that both the raw-message
//! hook and the `SpoofSuspected` anomaly fire. Validates the full live
//! path: capture → zero-copy drain → `arp::parse_frame` → detector.
//!
//! Needs `CAP_NET_RAW` (i.e. `just setcap` or run as root) and the
//! `integration-tests` Cargo feature, so it doesn't trip a casual
//! `cargo nextest run`.
//!
//! Run with:
//!
//! ```sh
//! just setcap
//! cargo nextest run -p netring \
//!     --features "tokio,channel,arp,emit,integration-tests" \
//!     -E 'binary(arp_lo_spoof)'
//! ```

#![cfg(all(feature = "arp", feature = "tokio", feature = "integration-tests"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use netring::Injector;
use netring::prelude::*;

const SENDER_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
const TARGET_MAC: [u8; 6] = [0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb];
const SENDER_IP: [u8; 4] = [192, 0, 2, 50];

/// Build a gratuitous ARP-reply Ethernet frame that trips
/// `ArpMessage::is_likely_spoof` (padded to the 60-byte Ethernet minimum).
fn spoof_arp_frame() -> [u8; 60] {
    let mut f = [0u8; 60];
    // Ethernet header.
    f[0..6].copy_from_slice(&[0xff; 6]); // dst: broadcast
    f[6..12].copy_from_slice(&SENDER_MAC); // src
    f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ethertype: ARP
    // ARP payload.
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&2u16.to_be_bytes()); // oper: reply
    f[22..28].copy_from_slice(&SENDER_MAC); // sha
    f[28..32].copy_from_slice(&SENDER_IP); // spa
    f[32..38].copy_from_slice(&TARGET_MAC); // tha (≠ sha → spoof)
    f[38..42].copy_from_slice(&SENDER_IP); // tpa (== spa → gratuitous)
    f
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_lo_detects_arp_spoof() {
    let msgs = Arc::new(AtomicU32::new(0));
    let spoofs = Arc::new(AtomicU32::new(0));
    let m = Arc::clone(&msgs);
    let s = Arc::clone(&spoofs);

    let monitor_result = Monitor::builder()
        .interface("lo")
        // No warm-up gate matters here — SpoofSuspected fires regardless,
        // but keep it short so the test is robust to scheduling.
        .arp_warmup(Duration::from_millis(0))
        .on_arp(move |_msg, _ctx| {
            m.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .on_arp_anomaly(move |a, _ctx| {
            if a.kind == ArpAnomalyKind::SpoofSuspected {
                s.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
        .build();

    let monitor = match monitor_result {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::build failed (likely needs CAP_NET_RAW): {e}");
            return;
        }
    };

    // Inject ARP frames from a background thread for the run's duration.
    // The Injector's blocking sends don't belong on the tokio reactor;
    // a plain std thread loops until the stop flag is set.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_tx = Arc::clone(&stop);
    let injector_thread = std::thread::spawn(move || {
        let mut tx = match Injector::builder().interface("lo").build() {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Injector::build failed (likely needs CAP_NET_RAW): {e}");
                return;
            }
        };
        let frame = spoof_arp_frame();
        while !stop_tx.load(Ordering::Relaxed) {
            if let Some(mut slot) = tx.allocate(frame.len()) {
                slot.data_mut()[..frame.len()].copy_from_slice(&frame);
                slot.set_len(frame.len());
                slot.send();
            }
            let _ = tx.flush();
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    let dur = Duration::from_millis(700);
    let run_res = tokio::time::timeout(Duration::from_secs(5), monitor.run_for(dur)).await;
    stop.store(true, Ordering::Relaxed);
    let _ = injector_thread.join();

    match run_res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("monitor.run_for failed (likely CAP_NET_RAW missing): {e}");
            return;
        }
        Err(_) => panic!("monitor.run_for didn't honour its 700ms deadline within 5s"),
    }

    let got_msgs = msgs.load(Ordering::Relaxed);
    let got_spoofs = spoofs.load(Ordering::Relaxed);
    eprintln!("arp_lo_spoof: {got_msgs} ARP messages, {got_spoofs} spoof anomalies");
    assert!(got_msgs >= 1, "expected at least one parsed ARP message");
    assert!(
        got_spoofs >= 1,
        "expected at least one SpoofSuspected anomaly, got {got_spoofs}"
    );
}
