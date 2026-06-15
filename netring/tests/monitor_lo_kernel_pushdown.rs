//! Root-gated live test of the 0.25 packet tier + S2 kernel pushdown on `lo`.
//!
//! Until now the packet tier was only exercised via pcap replay, and the
//! kernel-prefilter union (S1/S2) was only checked with the `BpfFilter::matches`
//! software interpreter. This runs a real Monitor on `lo`:
//!
//! - a single narrow packet subscription (`udp` + `dst port MATCH`) is the only
//!   consumer, so the Monitor compiles `kernel_prefilter() == udp/MATCH` and
//!   applies it to the AF_PACKET socket via `set_filter`;
//! - a generator blasts ~10× as much non-matching UDP (`dst port NOISE`) as
//!   matching UDP on `lo`.
//!
//! Asserts the packet handler fires on the matching frames (packet tier works
//! on a live capture, and the auto-applied kernel filter doesn't shed traffic a
//! consumer wants), and reports the kernel-delivered count
//! ([`MonitorHealth::packets`]) — which, with the filter applied, reflects only
//! the matching frames, not the noise blast.
//!
//! Needs `CAP_NET_RAW` (root or `just setcap`); gated on `integration-tests`.

#![cfg(all(feature = "tokio", feature = "flow", feature = "integration-tests"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::subscription::packet;

const MATCH_PORT: u16 = 54545;
const NOISE_PORT: u16 = 54546;

/// Blast non-matching UDP at ~10:1 over matching UDP on `lo` for `dur`.
/// Returns `(matching_sent, noise_sent)`.
async fn blast_udp(dur: Duration) -> (u64, u64) {
    let tx = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let (mut matched, mut noise) = (0u64, 0u64);
    let deadline = tokio::time::Instant::now() + dur;
    while tokio::time::Instant::now() < deadline {
        if tx
            .send_to(b"match", ("127.0.0.1", MATCH_PORT))
            .await
            .is_ok()
        {
            matched += 1;
        }
        for _ in 0..10 {
            if tx
                .send_to(b"noise", ("127.0.0.1", NOISE_PORT))
                .await
                .is_ok()
            {
                noise += 1;
            }
        }
        tokio::task::yield_now().await;
    }
    (matched, noise)
}

#[tokio::test(flavor = "current_thread")]
async fn packet_tier_and_kernel_prefilter_on_live_lo() {
    let hits = Arc::new(AtomicU64::new(0));
    let h = Arc::clone(&hits);

    // The packet sub is the ONLY consumer → kernel_prefilter == udp/MATCH_PORT,
    // auto-applied to the AF_PACKET socket.
    let builder =
        Monitor::builder()
            .interface("lo")
            .subscribe(packet().udp().dst_port(MATCH_PORT).to(move |_view, _ctx| {
                h.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }));

    // Sanity: a packet-sub-only monitor really does compile a narrow filter.
    assert!(
        builder.kernel_prefilter().is_some(),
        "a single narrow packet sub should compile to a kernel prefilter",
    );

    let monitor = match builder.build() {
        Ok(m) => m,
        Err(e) => {
            // The only realistic build failure is missing CAP_NET_RAW — skip.
            eprintln!("Monitor::build failed (likely needs CAP_NET_RAW): {e}");
            return;
        }
    };

    let health = monitor.health();
    let dur = Duration::from_millis(800);
    let gen_task = tokio::spawn(blast_udp(dur));

    let run = tokio::time::timeout(Duration::from_secs(6), monitor.run_for(dur)).await;
    let (matched_sent, noise_sent) = gen_task.await.unwrap_or((0, 0));

    match run {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("monitor.run_for failed (likely CAP_NET_RAW missing): {e}");
            return;
        }
        Err(_) => panic!("monitor.run_for didn't honour its 800ms deadline within 6s"),
    }

    let fired = hits.load(Ordering::Relaxed);
    let delivered = health.packets();
    eprintln!(
        "sent {matched_sent} match / {noise_sent} noise; packet-tier fired {fired}; \
         kernel-delivered {delivered}",
    );

    assert!(
        fired >= 1,
        "packet tier should fire on live udp/{MATCH_PORT} (sent {matched_sent})",
    );
    // Kernel-narrowing signal: the socket received far fewer frames than the
    // noise blast — the cBPF filter shed the non-matching UDP before userspace.
    // Only assert when telemetry actually sampled (`delivered > 0`) so a
    // sampling gap can't false-fail; the `eprintln!` above shows the raw counts.
    if delivered > 0 && noise_sent > 50 {
        assert!(
            delivered < noise_sent,
            "kernel filter should shed the noise: delivered {delivered} \
             vs {noise_sent} noise frames sent",
        );
    }
}
