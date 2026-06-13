//! 0.22 §5.1 — `ShardedRunner` cross-shard merge API (build-wiring).
//!
//! The cross-thread worker↔shard protocol is unit-tested end-to-end in
//! `src/monitor/merge.rs` (no AF_PACKET needed). Actually *running* a
//! `ShardedRunner` opens AF_PACKET (needs `CAP_NET_RAW`), so here we
//! only assert the builder API composes + type-checks.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::ops::AddAssign;
use std::time::Duration;

use netring::config::FanoutMode;
use netring::monitor::ShardedRunner;
use netring::prelude::*;

#[derive(Default)]
struct ConnCount(u64);
impl AddAssign for ConnCount {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

#[test]
fn merge_state_and_on_merge_compose() {
    let _runner = ShardedRunner::new("lo", FanoutMode::Cpu, 7, 4, |_cpu| {
        Monitor::builder()
            .interface("lo")
            .fanout(FanoutMode::Cpu, 7)
            .protocol::<Tcp>()
            .state::<ConnCount>()
            .on_ctx::<FlowStarted<Tcp>>(|_e: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
                ctx.state_mut::<ConnCount>().0 += 1;
                Ok(())
            })
            .build()
    })
    // explicit fold
    .merge_state::<ConnCount, _>(Duration::from_secs(1), |primary: &mut ConnCount, shard| {
        primary.0 += shard.0;
    })
    // …or the AddAssign auto-merge (on a second type)
    .state_auto_merge::<ConnCount>(Duration::from_secs(1))
    .on_merge::<ConnCount, _>(|total: &ConnCount| {
        let _ = total.0;
    });
}
