//! Integration test for fanout.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::{CaptureBuilder, FanoutFlags, FanoutMode, PacketSource};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn fanout_two_sockets() {
    let port = helpers::unique_port();
    let marker = format!("fanout_test_{port}");

    let counters: Vec<Arc<AtomicU64>> = (0..2).map(|_| Arc::new(AtomicU64::new(0))).collect();

    let handles: Vec<_> = (0..2)
        .map(|i| {
            let counter = Arc::clone(&counters[i]);
            let marker = marker.clone();

            thread::spawn(move || {
                let mut rx = CaptureBuilder::default()
                    .interface(helpers::LOOPBACK)
                    .fanout(FanoutMode::Hash, 9999)
                    .fanout_flags(FanoutFlags::ROLLOVER)
                    .block_timeout_ms(10)
                    .build()
                    .expect("build fanout rx");

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

    // Send packets with varying src ports to distribute across hash buckets
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
