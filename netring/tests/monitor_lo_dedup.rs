//! Root-gated: `MonitorBuilder::dedup_loopback` (#178) on the real `lo`
//! interface, where AF_PACKET delivers every frame twice (outgoing +
//! host). With the loopback profile each datagram reaches the handlers
//! once and the twins show up in `CaptureTelemetry::dedup_dropped`.
//! Needs `CAP_NET_RAW` (`just setcap`); skips gracefully without it.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "integration-tests"
))]

mod helpers;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use netring::monitor::{CaptureTelemetry, Monitor};
use netring::protocol::builtin::Udp;
use netring::protocol::event_typed::FlowPacket;

#[tokio::test(flavor = "current_thread")]
async fn loopback_dedup_delivers_each_datagram_once() {
    const N: usize = 20;
    let port = helpers::unique_port();
    let marker = b"netring-dedup-lo";

    let packets = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let (p, d) = (packets.clone(), dropped.clone());
    let monitor = match Monitor::builder()
        .interface(helpers::LOOPBACK)
        .dedup_loopback()
        .protocol::<Udp>()
        .on::<FlowPacket>(move |ev: &FlowPacket| {
            if ev.key.a.port() == port || ev.key.b.port() == port {
                p.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
        .on_capture_stats(Duration::from_millis(50), move |t: &CaptureTelemetry, _| {
            d.fetch_max(t.dedup_dropped, Ordering::Relaxed);
            Ok(())
        })
        .build()
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::build failed (likely needs CAP_NET_RAW): {e}");
            return;
        }
    };

    // Traffic once the ring is surely open; the deadline stops the run.
    // Generous margins: the CI lane is a loaded VM, and the last
    // telemetry sample (50 ms period) must land after the datagrams.
    let sender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        tokio::task::spawn_blocking(move || helpers::send_udp_to_loopback(port, marker, N))
            .await
            .unwrap();
    });
    let run = tokio::time::timeout(
        Duration::from_secs(10),
        monitor.run_for(Duration::from_millis(1_500)),
    )
    .await;
    sender.abort();
    match run {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("monitor.run_for failed (likely CAP_NET_RAW missing): {e}");
            return;
        }
        Err(_) => panic!("run_for did not honour its deadline"),
    }

    let seen = packets.load(Ordering::Relaxed);
    let dropped = dropped.load(Ordering::Relaxed);
    eprintln!("monitor_lo_dedup: {seen} packets on port {port}, {dropped} dropped as duplicates");
    assert_eq!(seen, N, "each datagram reaches the handlers exactly once");
    assert!(
        dropped >= N as u64,
        "the loopback twins were dropped: {dropped}"
    );
}
