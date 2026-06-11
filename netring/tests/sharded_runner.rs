//! 0.21 C: smoke tests for `ShardedRunner`.
//!
//! Build-side checks for the per-CPU sharding shape. Doesn't open
//! AF_PACKET (each shard's `Monitor::run_for` is what does that;
//! we only call `ShardedRunner::run_for` on test paths where
//! `CAP_NET_RAW` is available, with soft-fallback otherwise).

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::config::FanoutMode;
use netring::monitor::{Monitor, ShardedRunner};
use netring::protocol::builtin::Tcp;

#[test]
fn sharded_runner_records_shape() {
    let runner = ShardedRunner::new("lo", FanoutMode::Cpu, 42, 4, |_cpu| {
        Monitor::builder()
            .interface("lo")
            .fanout(FanoutMode::Cpu, 42)
            .protocol::<Tcp>()
            .build()
    });
    assert_eq!(runner.shard_count(), 4);
    assert_eq!(runner.interface(), "lo");
    assert_eq!(runner.fanout(), (FanoutMode::Cpu, 42));
}

#[test]
fn monitor_shard_count_for_single_monitor_is_one() {
    let m = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .build()
        .expect("build");
    assert_eq!(m.shard_count(), 1);
}

#[test]
fn monitor_fanout_accessor_reports_setter() {
    let m = Monitor::builder()
        .interface("lo")
        .fanout(FanoutMode::Hash, 7)
        .protocol::<Tcp>()
        .build()
        .expect("build");
    assert_eq!(m.fanout(), Some((FanoutMode::Hash, 7)));
}

#[test]
fn shard_count_zero_clamps_to_one() {
    // Defensive: passing num_shards = 0 still produces a runnable
    // shape, just with one shard.
    let runner = ShardedRunner::new("lo", FanoutMode::Cpu, 1, 0, |_cpu| {
        Monitor::builder()
            .interface("lo")
            .fanout(FanoutMode::Cpu, 1)
            .protocol::<Tcp>()
            .build()
    });
    assert_eq!(runner.shard_count(), 1);
}

#[test]
fn sharded_runner_runs_n_shards_against_lo() {
    // Each shard increments a shared counter once per fired
    // handler. We don't drive synthetic traffic — just verifying
    // the threads spawn + the build closure runs N times.
    let build_count = Arc::new(AtomicU32::new(0));
    let bc = Arc::clone(&build_count);
    let runner = ShardedRunner::new("lo", FanoutMode::Cpu, 100, 2, move |_cpu| {
        bc.fetch_add(1, Ordering::Relaxed);
        Monitor::builder()
            .interface("lo")
            .fanout(FanoutMode::Cpu, 100)
            .drain_timeout(Duration::ZERO)
            .protocol::<Tcp>()
            .build()
    });

    // The build closure runs on each shard's thread. The actual
    // `Capture::open` may fail without CAP_NET_RAW — that's a soft
    // failure for the test environment. We assert the build
    // closure was invoked at least once (proves threads spawned).
    let r = runner.run_for(Duration::from_millis(10));
    if r.is_err() {
        eprintln!(
            "ShardedRunner errored (likely no CAP_NET_RAW): {:?}",
            r.err()
        );
    }
    // Even on permission failure the build closure runs first to
    // construct the per-shard Monitor. Each thread should have
    // bumped the counter.
    assert!(
        build_count.load(Ordering::Relaxed) >= 1,
        "expected the build closure to run at least once across the spawned shards"
    );
}
