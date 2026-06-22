//! Bounded-iteration tests for Capture::packets_for / packets_until.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::Capture;
use std::time::{Duration, Instant};

#[test]
fn packets_for_terminates_on_idle_lo() {
    let mut cap = Capture::builder()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build capture");

    let target = Duration::from_millis(200);
    let start = Instant::now();
    let mut pkts = cap.packets_for(target);
    let mut count = 0u64;
    while pkts.next_packet().is_some() {
        count += 1;
    }
    let _ = count;
    let elapsed = start.elapsed();

    // Allow a generous wall-clock margin (CI runners are noisy).
    assert!(
        elapsed < Duration::from_secs(2),
        "packets_for did not terminate within 2s on idle lo (took {elapsed:?})"
    );
    // Also expect we didn't return absurdly fast — packets_for should at
    // least try to wait the requested duration.
    assert!(
        elapsed >= target / 2,
        "packets_for returned suspiciously early ({elapsed:?})"
    );
}

#[test]
fn packets_until_past_deadline_yields_none() {
    let mut cap = Capture::builder()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build capture");

    // Deadline already in the past — should return None on first pull.
    let past = Instant::now() - Duration::from_secs(1);
    let mut pkts = cap.packets_until(past);
    assert!(pkts.next_packet().is_none());
}
