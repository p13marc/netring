//! 0.25 C3: cap-free **userspace dispatch throughput** benchmark — a pps proxy
//! for the part of the pipeline netring controls (flow tracking + event
//! dispatch), measurable without a NIC or privileges.
//!
//! It does NOT measure kernel→userspace capture rate (that needs a real NIC and
//! is the hardware-gated half of `docs/PERFORMANCE.md`). It measures how fast a
//! fixed batch of synthetic frames is tracked through a flowscope `Driver` —
//! the per-packet cost the run loop pays after the zero-copy read. Use it to
//! catch regressions in the tracking/extraction hot path and to size the
//! userspace ceiling.
//!
//! Run: `cargo bench --features flow --bench dispatch_throughput`

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use etherparse::PacketBuilder;
use flowscope::driver::Driver;
use flowscope::extract::FiveTuple;

/// Build one TCP/IPv4 frame on a distinct source port (→ distinct flow).
fn tcp_frame(sport: u16, dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(sport, dport, 0, 1024);
    let mut frame = Vec::with_capacity(64);
    b.write(&mut frame, &[]).unwrap();
    frame
}

fn bench_track_into(c: &mut Criterion) {
    const N: usize = 4096;
    // A spread of source ports → ~64 concurrent flows, so the batch exercises
    // both new-flow creation and established-flow updates.
    let frames: Vec<Vec<u8>> = (0..N)
        .map(|i| tcp_frame(20000 + (i % 64) as u16, 443))
        .collect();
    let ts = flowscope::Timestamp::from_unix_f64(1000.0);

    let mut group = c.benchmark_group("dispatch");
    group.throughput(Throughput::Elements(N as u64));
    group.bench_function("track_into_4096_frames_64_flows", |b| {
        b.iter(|| {
            // Fresh driver per batch keeps the measurement deterministic (flows
            // don't accumulate across criterion iterations); the build cost
            // amortises over N frames.
            let mut driver = Driver::builder(FiveTuple::bidirectional()).build();
            let mut events = Vec::with_capacity(8);
            for f in &frames {
                events.clear();
                driver.track_into(flowscope::PacketView::new(f, ts), &mut events);
            }
            std::hint::black_box(driver.tracker().flow_count());
        });
    });
    group.finish();
}

criterion_group!(benches, bench_track_into);
criterion_main!(benches);
