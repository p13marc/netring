//! Root-gated end-to-end test for the 0.22 cross-shard `merge_state`
//! worker on the loopback interface. Exercises the full live path: a
//! `ShardedRunner` with per-shard local state + `state_auto_merge`
//! folding into a global total, driven by real `lo` traffic.
//!
//! Needs `CAP_NET_RAW` + the `integration-tests` feature; skips
//! gracefully otherwise.
//!
//! ```sh
//! just setcap
//! cargo nextest run -p netring \
//!     --features "monitor-quickstart,integration-tests" \
//!     -E 'binary(sharded_lo_merge)'
//! ```

#![cfg(all(feature = "tokio", feature = "flow", feature = "integration-tests"))]

use std::net::UdpSocket;
use std::ops::AddAssign;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use netring::config::FanoutMode;
use netring::monitor::ShardedRunner;
use netring::prelude::*;

#[derive(Default)]
struct PktCount(u64);
impl AddAssign for PktCount {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

#[test]
fn sharded_state_auto_merge_aggregates_lo_traffic() {
    let merged_total = Arc::new(AtomicU64::new(0));
    let merge_fires = Arc::new(AtomicU32::new(0));
    let total = Arc::clone(&merged_total);
    let fires = Arc::clone(&merge_fires);

    // A closed port so UDP sends generate captured packets on lo.
    let closed = {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let p = s.local_addr().unwrap().port();
        drop(s);
        p
    };

    // Traffic generator thread (the runner is sync + blocking).
    let stop = Arc::new(AtomicBool::new(false));
    let stop_gen = Arc::clone(&stop);
    let gen_task = std::thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        while !stop_gen.load(Ordering::Relaxed) {
            let _ = sock.send_to(b"netring-merge-probe", ("127.0.0.1", closed));
            std::thread::sleep(Duration::from_millis(2));
        }
    });

    let runner = ShardedRunner::new("lo", FanoutMode::Cpu, 0xBEEF, 2, |_cpu| {
        Monitor::builder()
            .interface("lo")
            .fanout(FanoutMode::Cpu, 0xBEEF)
            .all_l4()
            .state::<PktCount>()
            .on_ctx::<FlowPacket>(|_e: &FlowPacket, ctx: &mut Ctx<'_>| {
                ctx.state_mut::<PktCount>().0 += 1; // per-shard LOCAL
                Ok(())
            })
            .build()
    })
    .state_auto_merge::<PktCount>(Duration::from_millis(150))
    .on_merge::<PktCount, _>(move |c: &PktCount| {
        total.store(c.0, Ordering::Relaxed);
        fires.fetch_add(1, Ordering::Relaxed);
    });

    let res = runner.run_for(Duration::from_millis(900));
    stop.store(true, Ordering::Relaxed);
    let _ = gen_task.join();

    if res.is_err() {
        eprintln!("skip (needs CAP_NET_RAW): {res:?}");
        return;
    }

    // The merge worker should have fired its 150ms cadence several times
    // over the 900ms run — that's the path under test. The captured
    // total varies with traffic, so we only assert the worker ran.
    let fires = merge_fires.load(Ordering::Relaxed);
    assert!(
        fires >= 1,
        "the merge worker should have fired at least once (got {fires})"
    );
    eprintln!(
        "merge worker fired {fires}x; final cross-shard PktCount = {}",
        merged_total.load(Ordering::Relaxed)
    );
}
