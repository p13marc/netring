//! Root-gated TX-timestamp test on `lo` (0.25 W3).
//!
//! Builds an `Injector` with `tx_timestamps(true)`, sends a frame on loopback,
//! and reads the **software** egress timestamp back off the socket error queue
//! (`SO_TIMESTAMPING` → `SCM_TIMESTAMPING`). Software TX timestamps are
//! generated on `lo`, so this validates the full enable → send → error-queue
//! read path without needing a timestamping NIC.
//!
//! Gated behind `integration-tests` + `tokio`; gracefully skips without
//! `CAP_NET_RAW`. Run under `sudo` in CI.

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

use std::time::Duration;

use netring::{AsyncInjector, Injector};

#[tokio::test]
async fn software_tx_timestamp_round_trips_on_lo() {
    let injector = match Injector::builder()
        .interface("lo")
        .tx_timestamps(true)
        .build()
    {
        Ok(t) => t,
        Err(_) => return, // no CAP_NET_RAW (or lo unavailable) → skip
    };
    let mut tx = AsyncInjector::new(injector).expect("wrap injector");

    // A minimal 64-byte frame: AF_PACKET SOCK_RAW transmits it verbatim on lo.
    let frame = [0u8; 64];
    tx.send(&frame).await.expect("send");
    tx.flush().await.expect("flush");
    let _ = tx.wait_drained(Duration::from_secs(1)).await;

    // The kernel queues the egress timestamp asynchronously; poll briefly.
    let mut got = None;
    for _ in 0..100 {
        if let Some(ts) = tx.read_tx_timestamp() {
            got = Some(ts);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let ts = got.expect("expected a software TX timestamp from the error queue on lo");
    // Sanity: a real wall-clock timestamp (post-2020), not a zero/garbage value.
    assert!(
        ts.to_unix_f64() > 1_600_000_000.0,
        "TX timestamp looks wrong: {ts:?}"
    );
}

/// 0.25 W3: `AsyncInjector::send_stream` transmits every frame from a stream,
/// paced by a `TxPacer`. Root-gated (opens a TX socket on lo); skips without
/// CAP_NET_RAW. Asserts the reported sent-count and that pacing actually
/// throttles (10 frames at 100 pps takes ≳ ~90 ms).
#[tokio::test]
async fn send_stream_transmits_all_frames_paced() {
    use netring::TxPacer;

    let injector = match Injector::open("lo") {
        Ok(t) => t,
        Err(_) => return, // no CAP_NET_RAW → skip
    };
    let mut tx = AsyncInjector::new(injector).expect("wrap injector");

    let frames = futures::stream::iter((0..10u32).map(|_| vec![0u8; 64]));
    let start = std::time::Instant::now();
    let sent = tx
        .send_stream(frames, Some(TxPacer::packets_per_second(100.0)))
        .await
        .expect("send_stream");
    let elapsed = start.elapsed();

    assert_eq!(sent, 10, "all frames should be sent");
    // 10 frames at 100 pps: the first is free (burst), the next 9 each wait
    // ~10 ms → ≳ ~80 ms total. Generous lower bound to avoid flakiness.
    assert!(
        elapsed >= Duration::from_millis(50),
        "pacing should throttle the stream; took {elapsed:?}"
    );
}
