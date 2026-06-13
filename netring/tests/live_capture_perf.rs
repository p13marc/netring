//! Root-gated live-capture performance harness (0.24 Phase A5).
//!
//! Measures the high-level `Monitor` run loop on real loopback traffic:
//! **packets/sec** and **heap allocations per packet**. This is the
//! before/after instrument for the 0.24 Phase B keystone — today the Monitor
//! copies every packet out of the ring (`Packet::to_owned`), so the per-packet
//! alloc count is non-trivial; the borrowed-batch rewrite should drive it toward
//! zero. The dhat `bench-zero-alloc` bench already proves the *dispatch* path is
//! Δ0; this proves the *capture→dispatch* path.
//!
//! Caveat: the global allocator counts the whole process during the armed
//! window (the in-process traffic generator + tokio internals + the run loop),
//! so the absolute number is an upper bound. The *signal* — whether it scales
//! ~1/packet — is what Phase B moves. Run with:
//!   `just setcap && cargo test -p netring --features integration-tests,tokio,flow \
//!        --test live_capture_perf -- --nocapture`
#![cfg(all(feature = "tokio", feature = "flow", feature = "integration-tests"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use netring::prelude::*;

// ── Counting global allocator (this test binary only) ──────────────────────

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding to the system allocator with the same layout.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: forwarding a pointer/layout pair we previously returned.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: as `dealloc`/`alloc`.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Blast UDP datagrams at a loopback port until `deadline`, counting sends.
async fn flood_lo(port: u16, deadline: Instant, sent: Arc<AtomicU64>) {
    let Ok(udp) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return;
    };
    while Instant::now() < deadline {
        for _ in 0..64 {
            if udp
                .send_to(b"netring-perf-probe", ("127.0.0.1", port))
                .await
                .is_ok()
            {
                sent.fetch_add(1, Ordering::Relaxed);
            }
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn live_capture_pps_and_allocs() {
    let port = 39_517u16;
    let packets = Arc::new(AtomicU64::new(0));
    let p2 = Arc::clone(&packets);

    // A minimal monitor: count every captured L4 packet. The handler does no
    // allocation, so any per-packet alloc comes from the capture→dispatch path.
    let monitor = match Monitor::builder()
        .interface("lo")
        .protocol::<Udp>()
        .on::<FlowPacket>(move |_pkt: &FlowPacket| {
            p2.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("skip: build failed ({e:?})");
            return;
        }
    };

    let run_dur = Duration::from_secs(2);
    let sent = Arc::new(AtomicU64::new(0));
    let gen_task = tokio::spawn(flood_lo(port, Instant::now() + run_dur, Arc::clone(&sent)));

    // Warm up briefly (socket bind, first packets), THEN arm the allocator so
    // one-time setup isn't counted. Measure over the steady-state window.
    let warmup = Duration::from_millis(300);
    let armed_after = packets.clone();
    let arm = tokio::spawn(async move {
        tokio::time::sleep(warmup).await;
        let base_pkts = armed_after.load(Ordering::Relaxed);
        ALLOCS.store(0, Ordering::Relaxed);
        ARMED.store(true, Ordering::Relaxed);
        base_pkts
    });

    let t0 = Instant::now();
    let run =
        tokio::time::timeout(run_dur + Duration::from_secs(3), monitor.run_for(run_dur)).await;
    ARMED.store(false, Ordering::Relaxed);
    let elapsed = t0.elapsed();
    let base_pkts = arm.await.unwrap_or(0);
    let _ = gen_task.await;

    match &run {
        Err(_) => {
            eprintln!("skip: run_for timed out");
            return;
        }
        Ok(Err(e)) => {
            eprintln!("skip: run_for errored (likely missing CAP_NET_RAW): {e:?}");
            return;
        }
        Ok(Ok(())) => {}
    }

    let total_pkts = packets.load(Ordering::Relaxed);
    let measured_pkts = total_pkts.saturating_sub(base_pkts);
    let allocs = ALLOCS.load(Ordering::Relaxed);

    if measured_pkts == 0 {
        eprintln!("skip: no packets captured on lo (no CAP_NET_RAW?)");
        return;
    }

    let pps = total_pkts as f64 / elapsed.as_secs_f64();
    let allocs_per_pkt = allocs as f64 / measured_pkts as f64;
    eprintln!(
        "live-capture: {total_pkts} pkts in {:.2}s = {pps:.0} pps; \
         allocs/pkt (armed window, incl. gen+runtime noise) = {allocs_per_pkt:.2} \
         ({allocs} allocs / {measured_pkts} pkts)",
        elapsed.as_secs_f64()
    );

    // Sanity bounds (loose — this is a reporting instrument, not a tight gate
    // yet). 0.24 Phase B drives `allocs_per_pkt` down by removing the
    // per-packet `to_owned` copy in the run loop; that's when this becomes a
    // strict assertion.
    assert!(pps > 0.0, "captured packets but computed zero pps");
    assert!(
        allocs_per_pkt < 100.0,
        "allocs/pkt unexpectedly high ({allocs_per_pkt:.1}) — pathological allocation?"
    );
}
