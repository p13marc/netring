//! #146: a capture blocked on an idle interface can be stopped from
//! another thread, and `next_packet_timeout` hands control back on
//! every poll timeout.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::time::{Duration, Instant};

use netring::CaptureBuilder;

/// A filter no loopback packet matches keeps the capture idle.
fn idle_capture() -> netring::Capture {
    let filter = netring::BpfFilter::builder()
        .udp()
        .dst_port(helpers::unique_port())
        .build()
        .expect("filter");
    CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .bpf_filter(filter)
        .poll_timeout(Duration::from_secs(30))
        .build()
        .expect("build rx")
}

#[test]
fn stop_handle_wakes_a_blocked_for_each() {
    let mut cap = idle_capture();
    let stop = cap.stop_handle().expect("eventfd");
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        stop.stop();
    });
    let start = Instant::now();
    let mut n = 0usize;
    cap.packets().for_each(|_| n += 1);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "stopped long before the 30 s poll timeout"
    );
    assert_eq!(n, 0);
    t.join().unwrap();
    assert!(cap.stop_requested());
    // Stays stopped until cleared.
    assert!(cap.packets().next_packet().is_none());
    cap.clear_stop();
    assert!(!cap.stop_requested());
}

#[test]
fn next_packet_timeout_returns_on_an_idle_interface() {
    let mut cap = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .bpf_filter(
            netring::BpfFilter::builder()
                .udp()
                .dst_port(helpers::unique_port())
                .build()
                .expect("filter"),
        )
        .poll_timeout(Duration::from_millis(50))
        .build()
        .expect("build rx");
    let start = Instant::now();
    let mut pkts = cap.packets();
    // Frames that reached the socket before its filter was attached
    // may come first; after them, an idle poll hands control back.
    let mut idle = false;
    for _ in 0..10_000 {
        if pkts.next_packet_timeout().expect("no error").is_none() {
            idle = true;
            break;
        }
    }
    assert!(idle, "a poll timeout returned None");
    assert!(start.elapsed() < Duration::from_secs(5));
}
