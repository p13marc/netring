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
