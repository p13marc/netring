//! Integration tests for plan 21: `AsyncCapture::open_with_filter`
//! and `Capture::set_filter` / `AsyncCapture::set_filter`.
//!
//! Requires `CAP_NET_RAW`. Run with:
//!   cargo test --features integration-tests,tokio,flow,parse

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

mod helpers;

use std::time::Duration;

use netring::{AsyncCapture, BpfFilter, PacketSetFilter};

#[tokio::test(flavor = "current_thread")]
async fn open_with_filter_attaches_before_first_packet() {
    let port_match = helpers::unique_port();
    let port_miss = helpers::unique_port();
    let marker = format!("openwithfilter_{port_match}");

    // Filter accepting only dst_port=port_match.
    let filter = BpfFilter::builder()
        .udp()
        .dst_port(port_match)
        .build()
        .expect("BpfFilter::builder");

    // `AsyncCapture::open_with_filter` calls `AsyncFd::new` internally,
    // which needs a running tokio reactor — hence `#[tokio::test]`.
    let mut cap = AsyncCapture::open_with_filter(helpers::LOOPBACK, filter)
        .expect("open_with_filter");

    // Send to the non-matching port first — kernel should drop it.
    helpers::send_udp_to_loopback(port_miss, marker.as_bytes(), 3);
    // Then send to the matching port.
    helpers::send_udp_to_loopback(port_match, marker.as_bytes(), 3);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut saw_match = false;
    let mut saw_miss = false;
    while std::time::Instant::now() < deadline {
        let batch = match cap
            .get_mut()
            .next_batch_blocking(Duration::from_millis(100))
        {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(_) => break,
        };
        for pkt in &batch {
            let data = pkt.data();
            if data.windows(marker.len()).any(|w| w == marker.as_bytes()) {
                let port_match_bytes = port_match.to_be_bytes();
                let port_miss_bytes = port_miss.to_be_bytes();
                if data.windows(2).any(|w| w == port_match_bytes) {
                    saw_match = true;
                }
                if data.windows(2).any(|w| w == port_miss_bytes) {
                    saw_miss = true;
                }
            }
        }
        drop(batch);
        if saw_match {
            break;
        }
    }
    assert!(saw_match, "expected to see port_match traffic");
    assert!(
        !saw_miss,
        "filter should have blocked port_miss traffic, but saw it"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn set_filter_swaps_at_runtime() {
    let port_a = helpers::unique_port();
    let port_b = helpers::unique_port();
    let marker = format!("setfilter_{port_a}_{port_b}");

    // Start with a filter matching port_a only. Construction needs a
    // running reactor — see `open_with_filter_attaches_before_first_packet`.
    let filter_a = BpfFilter::builder()
        .udp()
        .dst_port(port_a)
        .build()
        .expect("build a");
    let mut cap =
        AsyncCapture::open_with_filter(helpers::LOOPBACK, filter_a).expect("open_with_filter");

    // Swap to a filter matching port_b only.
    let filter_b = BpfFilter::builder()
        .udp()
        .dst_port(port_b)
        .build()
        .expect("build b");
    cap.set_filter(&filter_b).expect("set_filter");

    // Send to port_a (now blocked) and port_b (now allowed).
    helpers::send_udp_to_loopback(port_a, marker.as_bytes(), 3);
    helpers::send_udp_to_loopback(port_b, marker.as_bytes(), 3);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut saw_a = false;
    let mut saw_b = false;
    while std::time::Instant::now() < deadline {
        let batch = match cap
            .get_mut()
            .next_batch_blocking(Duration::from_millis(100))
        {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(_) => break,
        };
        for pkt in &batch {
            let data = pkt.data();
            if data.windows(marker.len()).any(|w| w == marker.as_bytes()) {
                let a_be = port_a.to_be_bytes();
                let b_be = port_b.to_be_bytes();
                if data.windows(2).any(|w| w == a_be) {
                    saw_a = true;
                }
                if data.windows(2).any(|w| w == b_be) {
                    saw_b = true;
                }
            }
        }
        drop(batch);
        if saw_b {
            break;
        }
    }
    assert!(saw_b, "expected to see port_b traffic under filter_b");
    assert!(
        !saw_a,
        "filter_b should have blocked port_a traffic, but saw it"
    );
}

#[test]
fn capture_set_filter_trait_object() {
    // Sanity: the `PacketSetFilter` trait is in scope and bound for `Capture`.
    use netring::{Capture, CaptureBuilder};
    let cap: Capture = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build");
    let filter = BpfFilter::builder()
        .tcp()
        .dst_port(443)
        .build()
        .expect("filter");
    // Through inherent method:
    cap.set_filter(&filter).expect("inherent set_filter");
    // Through trait method:
    <Capture as PacketSetFilter>::set_filter(&cap, &filter).expect("trait set_filter");
}
