//! `AsyncInjector::send` on a full TX ring.
//!
//! Frames queued with `send` are only transmitted when the kernel is
//! kicked (`sendto`), so a ring full of queued frames never frees a slot on
//! its own: `send` has to kick before it waits for one.
//!
//! Requires CAP_NET_RAW. Run with:
//! cargo test --features integration-tests,tokio --test async_injector

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

mod helpers;

use std::time::Duration;

use helpers::PluggedDummy;
use netring::{AsyncInjector, Injector};

/// More sends than the ring has frames, with no `flush` in between.
#[tokio::test]
async fn send_past_a_full_ring_does_not_hang() {
    let injector = Injector::builder()
        .interface("lo")
        .frame_count(8)
        .build()
        .expect("build injector");
    assert_eq!(injector.frame_count(), 8);
    let mut tx = AsyncInjector::new(injector).expect("wrap injector");

    let mut frame = [0u8; 64];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    let all = async {
        for _ in 0..32 {
            tx.send(&frame).await?;
        }
        tx.flush().await
    };
    let result = tokio::time::timeout(Duration::from_secs(2), all).await;
    result
        .expect("32 sends into an 8-frame ring hung")
        .expect("send / flush");
}

/// #228: an async kick doesn't wait for the device. A flags-0 `sendto` on
/// a TX ring waits until every frame it handed over completes
/// (tpacket_snd(): `need_wait`), which a device that holds frames — here a
/// `plug` qdisc — may never do; `AsyncInjector::flush` made that blocking
/// call on the runtime thread. It now kicks with `MSG_DONTWAIT`.
#[tokio::test(flavor = "current_thread")]
async fn async_flush_does_not_wait_for_the_device() {
    let Some(dummy) = PluggedDummy::create() else {
        eprintln!("skip: cannot create a plugged dummy (needs CAP_NET_ADMIN, sch_plug)");
        return;
    };
    let injector = Injector::builder()
        .interface(&dummy.0)
        .frame_count(8)
        .build()
        .expect("build injector");
    let mut tx = AsyncInjector::new(injector).expect("wrap injector");
    let mut frame = [0u8; 64];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    for _ in 0..4 {
        tx.send(&frame).await.expect("queue");
    }
    // Releases the frames — by deleting the device — after 3 s, so a
    // blocking kick ends rather than hangs the test.
    let name = dummy.0.clone();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &name])
            .output();
    });
    let start = std::time::Instant::now();
    let kicked = tx.flush().await.expect("kick");
    let elapsed = start.elapsed();
    assert_eq!(kicked, 4);
    assert!(
        elapsed < Duration::from_secs(1),
        "flush waited {elapsed:?} for the device"
    );
    // Handed to the device, held by the qdisc: not drained.
    assert!(tx.pending_count() > 0, "frames are in flight");
    release.join().unwrap();
    drop(dummy);
}
