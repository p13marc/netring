//! `AsyncInjector::send` on a full TX ring.
//!
//! Frames queued with `send` are only transmitted when the kernel is
//! kicked (`sendto`), so a ring full of queued frames never frees a slot on
//! its own: `send` has to kick before it waits for one.
//!
//! Requires CAP_NET_RAW. Run with:
//! cargo test --features integration-tests,tokio --test async_injector

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

use std::time::Duration;

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
