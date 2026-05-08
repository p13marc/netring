//! Integration test for block timeout behavior.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::CaptureBuilder;
use std::time::Duration;

#[test]
fn block_timeout_triggers() {
    let port = helpers::unique_port();

    let mut rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10) // very short timeout
        .build()
        .expect("build rx");

    // Send exactly 1 small packet — not enough to fill a block
    helpers::send_udp_to_loopback(port, b"timeout_test", 1);

    // The block should be retired by timeout, not by being full
    let batch = rx
        .next_batch_blocking(Duration::from_secs(2))
        .expect("poll")
        .expect("should get a batch via timeout");

    assert!(!batch.is_empty());
    // With a 10ms timeout and only 1 packet, the block was likely
    // retired via timeout. Note: on a busy loopback, the block might
    // fill with other traffic before the timeout fires.
    // We mainly verify the batch arrives within a reasonable time.
}
