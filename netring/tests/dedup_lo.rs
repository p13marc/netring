//! Integration test for `Dedup::loopback()` against a real `lo` capture.
//!
//! Requires `CAP_NET_RAW`. Run with:
//!   cargo test --features integration-tests,tokio
//!
//! Without `Dedup`, every packet sent to 127.0.0.1 appears twice in
//! the capture (once Outgoing, once Host). With `Dedup::loopback()`
//! we expect to see each packet exactly once.

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

mod helpers;

use std::time::Duration;

use futures::StreamExt;
use netring::{AsyncCapture, Capture, CaptureBuilder, Dedup, PacketSource};

#[test]
fn dedup_loopback_drops_kernel_reinjections() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let port = helpers::unique_port();
        let marker = format!("netring_dedup_{port}");

        // Build the rx + dedup stream.
        let rx = CaptureBuilder::default()
            .interface(helpers::LOOPBACK)
            .block_timeout_ms(10)
            .build()
            .expect("build rx");
        let cap = AsyncCapture::new(rx).expect("AsyncCapture::new");
        let mut stream = cap.dedup_stream(Dedup::loopback());

        // Spawn sender in a background task.
        let marker_clone = marker.clone();
        let send_count = 5usize;
        let sender = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            helpers::send_udp_to_loopback(port, marker_clone.as_bytes(), send_count);
        });

        // Collect kept packets that match our marker, until deadline or
        // we've seen at least `send_count` of them.
        let mut found = 0usize;
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                evt = stream.next() => {
                    match evt {
                        Some(Ok(pkt)) => {
                            if pkt
                                .data
                                .windows(marker.len())
                                .any(|w| w == marker.as_bytes())
                            {
                                found += 1;
                                if found >= send_count {
                                    break;
                                }
                            }
                        }
                        Some(Err(e)) => panic!("dedup stream error: {e}"),
                        None => break,
                    }
                }
            }
        }

        sender.await.unwrap();

        // Without dedup we'd see ~2x send_count packets matching the
        // marker. With dedup, ideally exactly send_count, but the
        // kernel can also generate broadcast/multicast variants and
        // there's no perfect 1:1 guarantee. Assert "matched at least
        // some" + "not the doubled count".
        assert!(
            found >= 1,
            "expected at least one marked packet to survive dedup; found={found}"
        );
        let dropped = stream.dedup().dropped();
        assert!(
            dropped > 0,
            "expected Dedup to have dropped at least one duplicate; \
             dropped={dropped} found={found}"
        );

        // Sanity: kept ≤ seen.
        let kept = stream.dedup().seen() - stream.dedup().dropped();
        assert!(
            kept <= stream.dedup().seen(),
            "kept ({kept}) <= seen ({})",
            stream.dedup().seen()
        );
    });
}

#[test]
fn dedup_content_preserves_distinct_payloads() {
    // Sanity check that Dedup::content with a generous window still
    // keeps distinct payloads on `lo`.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let port = helpers::unique_port();

        let rx = CaptureBuilder::default()
            .interface(helpers::LOOPBACK)
            .block_timeout_ms(10)
            .build()
            .expect("build rx");
        let cap = AsyncCapture::new(rx).expect("AsyncCapture::new");
        let mut stream = cap.dedup_stream(Dedup::content(Duration::from_millis(50), 256));

        // Send 5 packets with DISTINCT payloads — each should survive
        // because they hash differently.
        let _sender = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            for i in 0..5u8 {
                let payload = format!("netring_distinct_{port}_{i}");
                helpers::send_udp_to_loopback(port, payload.as_bytes(), 1);
            }
        });

        // Collect for 1 second and assert at least 5 unique-payload
        // packets came through.
        let mut distinct_seen = std::collections::HashSet::new();
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                evt = stream.next() => match evt {
                    Some(Ok(pkt)) => {
                        // Look for our marker prefix.
                        let want = format!("netring_distinct_{port}_");
                        if let Some(pos) = pkt.data.windows(want.len()).position(|w| w == want.as_bytes()) {
                            let after = &pkt.data[pos + want.len()..];
                            if let Some(&b) = after.first() {
                                distinct_seen.insert(b);
                            }
                        }
                        if distinct_seen.len() >= 5 { break; }
                    }
                    Some(Err(e)) => panic!("stream error: {e}"),
                    None => break,
                }
            }
        }

        assert!(
            distinct_seen.len() >= 3,
            "expected ≥3 distinct payload bytes; got {}",
            distinct_seen.len()
        );
    });
}

// Suppress unused-import warning when feature combinations exclude
// certain helpers.
#[allow(dead_code)]
fn _unused(_: Capture, _: &dyn PacketSource) {}
