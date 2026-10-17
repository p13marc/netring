//! Owner-attributed bandwidth (issue #130).
//!
//! Cap-free build coverage + the AttributionHookRequired guard. The rate
//! computation itself is exercised by flowscope's BandwidthByKey tests.

#![cfg(all(feature = "tokio", feature = "flow"))]

use flowscope::correlate::Attribution;
use netring::monitor::Monitor;
use netring::prelude::StdoutSink;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn owner_bandwidth_builds_with_hook() {
    let m = Monitor::builder()
        .interface("lo")
        .with_flow_attribution(|key| Some(Attribution(u64::from(key.b.port()))))
        .owner_bandwidth()
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "owner_bandwidth build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
async fn on_owner_bandwidth_reports() {
    let m = Monitor::builder()
        .interface("lo")
        .with_flow_attribution(|_k| Some(Attribution(1)))
        .on_owner_bandwidth(Duration::from_secs(5), |r| {
            let _ = (r.top(10), r.unknown_share(), r.semantics());
            Ok(())
        })
        .build();
    assert!(m.is_ok(), "on_owner_bandwidth build failed: {:?}", m.err());
}

/// The per-flow owner cache is released when *any* flow ends, not only
/// TCP / UDP ones: a GRE flow (IP protocol 47, no `FlowEnded<P>` marker)
/// that idles out and comes back is attributed afresh — its stale entry
/// used to stay in the cache for good (and be reused).
#[cfg(all(feature = "pcap", feature = "parse"))]
#[tokio::test(flavor = "current_thread")]
async fn owner_cache_is_released_for_every_ended_flow() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    let mut gre = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
    gre.extend_from_slice(&[0x45, 0, 0, 24, 0, 0, 0, 0, 64, 47, 0, 0]);
    gre.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    gre.extend_from_slice(&[0, 0, 0x08, 0x00]); // GRE: no flags, IPv4 payload
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gre.pcap");
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(std::fs::File::create(&path).unwrap(), header).unwrap();
    // The "other protocols" idle timeout is 30 s: two separate flows of
    // two packets each.
    for t in [1, 2, 100, 101] {
        w.write_packet(&PcapPacket::new(
            Duration::from_secs(t),
            gre.len() as u32,
            &gre,
        ))
        .unwrap();
    }
    drop(w);

    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    Monitor::builder()
        .pcap_source(&path)
        .with_flow_attribution(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Some(Attribution(7))
        })
        .owner_bandwidth()
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2, "one attribution per flow");
}

#[tokio::test(flavor = "current_thread")]
async fn owner_bandwidth_without_hook_errors() {
    // owner_bandwidth() before with_flow_attribution() → build error.
    let m = Monitor::builder().interface("lo").owner_bandwidth().build();
    let err = match m {
        Ok(_) => panic!("expected a build error"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("attribution"),
        "expected AttributionHookRequired, got: {err}"
    );
}
