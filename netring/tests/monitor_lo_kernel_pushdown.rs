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

    // The packet sub is the ONLY traffic consumer → kernel_prefilter ==
    // udp/MATCH_PORT, auto-applied to the AF_PACKET socket. `on_capture_stats`
    // arms telemetry sampling (so `health.packets()` reflects the kernel
    // socket's RX count) — it consumes no traffic, so it does NOT widen the
    // kernel filter (the `kernel_prefilter().is_some()` assertion below holds).
    let builder = Monitor::builder()
        .interface("lo")
        .on_capture_stats(Duration::from_millis(100), |_telemetry, _ctx| Ok(()))
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

    // If the generator couldn't put traffic on the wire we can't judge the
    // kernel filter — skip the narrowing check (e.g. a no-egress sandbox).
    if noise_sent <= 50 {
        eprintln!("generator sent too little ({noise_sent}); skipping narrowing check");
        return;
    }

    // Telemetry was armed via `on_capture_stats`, so `delivered` is the
    // AF_PACKET socket's post-filter RX count. The proof of kernel pushdown:
    // the socket delivered FEWER frames than just the non-matching blast — only
    // possible if the cBPF `set_filter` shed the noise before userspace (with
    // no filter, delivered would include all ~`matched + noise` frames, well
    // above `noise_sent`).
    assert!(
        delivered > 0,
        "on_capture_stats should have sampled the kernel RX count, got 0",
    );
    assert!(
        delivered < noise_sent,
        "kernel prefilter should shed non-matching UDP: kernel delivered \
         {delivered} frames vs {noise_sent} noise frames sent — `set_filter` \
         narrowed RX to matching traffic before userspace",
    );
}
