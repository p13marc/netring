//! Integration tests for capture statistics (#186: every accessor returns
//! totals since the source was opened and never resets them).

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::{BpfFilter, Capture, CaptureStats, Error};
use std::time::{Duration, Instant};

/// A port no other process is likely to use at the same time (the shared
/// `helpers::unique_port` counter starts at the same value in every test
/// binary, and the host `lo` is shared with other sessions).
fn private_port(slot: u16) -> u16 {
    40_000 + (std::process::id() % 5_000) as u16 * 4 + slot
}

/// Open `builder`, or `None` (skip) without `CAP_NET_RAW`.
fn open(builder: netring::CaptureBuilder) -> Option<Capture> {
    match builder.build() {
        Ok(cap) => Some(cap),
        Err(Error::PermissionDenied) => {
            eprintln!("skipping: needs CAP_NET_RAW");
            None
        }
        Err(e) => panic!("build capture: {e}"),
    }
}

/// A capture of the UDP datagrams to `port` on `lo`, each seen once.
fn udp_capture(port: u16) -> Option<Capture> {
    open(
        Capture::builder()
            .interface(helpers::LOOPBACK)
            .ignore_outgoing(true)
            .block_timeout_ms(10)
            .bpf_filter(
                BpfFilter::builder()
                    .udp()
                    .dst_port(port)
                    .build()
                    .expect("filter"),
            ),
    )
}

/// Read and drop packets until `n` were seen or `timeout` passes.
fn drain(cap: &mut Capture, n: usize, timeout: Duration) -> usize {
    let mut seen = 0;
    let mut pkts = cap.packets_for(timeout);
    while seen < n {
        if pkts.next_packet().is_none() {
            break;
        }
        seen += 1;
    }
    seen
}

/// Poll `stats()` until `delivered` reaches `want` (the loopback RX path
/// runs in softirq context, so the last datagrams can trail `sendto`).
fn stats_once_delivered(cap: &Capture, want: u64) -> CaptureStats {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let s = cap.stats().expect("stats");
        if s.delivered >= want || Instant::now() >= deadline {
            return s;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// #186: `stats()` reads the kernel's destructive `PACKET_STATISTICS` but
/// returns the running total, so consecutive reads agree and a window is
/// `delta_since`. In 0.31 the second read returned 0.
#[test]
fn stats_are_lifetime_and_non_destructive() {
    let port = private_port(0);
    let Some(mut cap) = udp_capture(port) else {
        return;
    };

    helpers::send_udp_to_loopback(port, b"stats_lifetime_marker", 50);
    assert_eq!(drain(&mut cap, 50, Duration::from_secs(2)), 50, "drained");

    let s1 = stats_once_delivered(&cap, 50);
    let s2 = cap.stats().expect("stats");
    assert_eq!(s1, s2, "a second read with no traffic must not reset");
    assert_eq!(cap.stats().expect("stats"), s1);
    assert_eq!(s1.delivered, 50, "{s1}");
    assert_eq!(s1.drops, 0, "{s1}");
    assert_eq!(s1.received(), 50);

    helpers::send_udp_to_loopback(port, b"stats_lifetime_marker", 50);
    assert_eq!(drain(&mut cap, 50, Duration::from_secs(2)), 50, "drained");
    let s3 = stats_once_delivered(&cap, 100);
    assert_eq!(s3.delta_since(&s1).delivered, 50, "{s3} - {s1}");
    assert_eq!(s3.delivered, 100, "{s3}");

    // The trait accessor is the same total.
    let via_trait = netring::PacketSource::stats(&cap).expect("stats");
    assert_eq!(via_trait, s3);
}

/// #183 / #186: on an overflowed ring that is never read, `delivered` is
/// only what fit in the ring, `drops` the rest, and `received()` — the
/// kernel's `tp_packets` — every datagram that reached the socket.
#[test]
fn overflowed_ring_reports_drops_apart_from_delivered() {
    let port = private_port(1);
    let Some(cap) = open(
        Capture::builder()
            .interface(helpers::LOOPBACK)
            .ignore_outgoing(true)
            .block_size(4096)
            .block_count(2)
            .frame_size(2048)
            .block_timeout_ms(10)
            .bpf_filter(
                BpfFilter::builder()
                    .udp()
                    .dst_port(port)
                    .build()
                    .expect("filter"),
            ),
    ) else {
        return;
    };

    // Never read: two 4 KiB blocks hold a few dozen of these frames.
    helpers::send_udp_to_loopback(port, &[0x42; 200], 2000);
    std::thread::sleep(Duration::from_millis(100));

    let s = cap.stats().expect("stats");
    eprintln!("overflowed ring: {s}");
    assert!(s.drops > 0, "the ring should have overflowed: {s}");
    assert!(
        s.delivered <= 128,
        "only what fits in two 4 KiB blocks was delivered: {s}"
    );
    assert!(
        s.received() >= 2000,
        "every datagram reached the socket: {s}"
    );
    assert!(s.drop_ratio() > 0.9, "{s}");
    // Lifetime totals: reading again changes nothing.
    assert_eq!(cap.stats().expect("stats"), s);
}
