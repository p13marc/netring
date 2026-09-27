//! Integration test for fanout.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::{CaptureBuilder, FanoutFlags, FanoutMode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn fanout_two_sockets() {
    let port = helpers::unique_port();
    let marker = format!("fanout_test_{port}");
    // Not a hardcoded id: see `helpers::unique_fanout_group` — a group another
    // run still holds silently swallows our packets.
    let group = helpers::unique_fanout_group();

    let counters: Vec<Arc<AtomicU64>> = (0..2).map(|_| Arc::new(AtomicU64::new(0))).collect();
    // Both sockets must be open before the first packet goes out: on a
    // loaded CI runner, building two rings took longer than the fixed
    // sleep this test used to rely on, and every packet was sent into a
    // group nobody was reading yet (the lane's recurring red).
    let ready = Arc::new(Barrier::new(3));

    let handles: Vec<_> = (0..2)
        .map(|i| {
            let counter = Arc::clone(&counters[i]);
            let marker = marker.clone();
            let ready = Arc::clone(&ready);

            thread::spawn(move || {
                let mut rx = CaptureBuilder::default()
                    .interface(helpers::LOOPBACK)
                    .fanout(FanoutMode::Hash, group)
                    .fanout_flags(FanoutFlags::ROLLOVER)
                    .block_timeout_ms(10)
                    .build()
                    .expect("build fanout rx");
                ready.wait();

                let deadline = Instant::now() + Duration::from_secs(3);
                while Instant::now() < deadline {
                    if let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100)).unwrap()
                    {
                        for pkt in &batch {
                            if pkt
                                .data()
                                .windows(marker.len())
                                .any(|w| w == marker.as_bytes())
                            {
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    // Send packets with varying src ports to distribute across hash buckets,
    // once both sockets are in the group (and settled for a moment).
    ready.wait();
    thread::sleep(Duration::from_millis(200));
    for i in 0..50 {
        let payload = format!("{marker}_{i}");
        helpers::send_udp_to_loopback(port, payload.as_bytes(), 1);
    }

    for h in handles {
        h.join().unwrap();
    }

    let total: u64 = counters.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    assert!(
        total > 0,
        "at least some packets should be captured across fanout group"
    );
}
