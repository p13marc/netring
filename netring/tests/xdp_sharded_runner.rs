//! #213: `XdpShardedRunner` stops every shard when one fails.
//!
//! A two-queue veth gives the runner two shards; the second one's
//! Monitor fails to build. The first must stop with it — it used to keep
//! running to its deadline, with no sibling stop.
//!
//! Needs root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW) and the `veth`
//! module. Run with:
//! cargo test --features integration-tests,tokio,flow,af-xdp,xdp-loader --test xdp_sharded_runner

#![cfg(all(
    feature = "integration-tests",
    feature = "tokio",
    feature = "flow",
    feature = "af-xdp",
    feature = "xdp-loader"
))]

use std::process::Command;
use std::time::{Duration, Instant};

use netring::monitor::XdpShardedRunner;
use netring::protocol::builtin::Udp;
use netring::xdp::Queues;

/// A veth pair with two RX/TX queues per end; deleted on drop.
struct TwoQueueVeth(String, String);

impl TwoQueueVeth {
    fn create() -> Option<Self> {
        let pid = std::process::id() % 10_000;
        let (a, b) = (format!("nrxs{pid}a"), format!("nrxs{pid}b"));
        let _ = Command::new("ip").args(["link", "delete", &a]).output();
        let ok = |args: &[&str]| {
            Command::new("ip")
                .args(args)
                .status()
                .is_ok_and(|s| s.success())
        };
        #[rustfmt::skip]
        let added = ok(&[
            "link", "add", &a, "numrxqueues", "2", "numtxqueues", "2",
            "type", "veth", "peer", "name", &b, "numrxqueues", "2", "numtxqueues", "2",
        ]);
        if !added {
            return None;
        }
        let veth = Self(a, b);
        (ok(&["link", "set", &veth.0, "up"]) && ok(&["link", "set", &veth.1, "up"])).then_some(veth)
    }
}

impl Drop for TwoQueueVeth {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

#[test]
fn a_failing_shard_stops_its_siblings() {
    let Some(veth) = TwoQueueVeth::create() else {
        eprintln!("skip: needs CAP_NET_ADMIN to create veth");
        return;
    };
    match netring::xdp::queue_count(&veth.1) {
        Ok(2) => {}
        other => {
            eprintln!("skip: {} reports {other:?} queues, not 2", veth.1);
            return;
        }
    }
    let runner = XdpShardedRunner::new(&veth.1, Queues::Auto, |queue, builder| {
        let builder = builder.protocol::<Udp>();
        if queue == 1 {
            // Fails at build(): no attribution hook.
            builder.owner_bandwidth()
        } else {
            builder
        }
    });
    let start = Instant::now();
    let res = runner.run_for(Duration::from_secs(10));
    let elapsed = start.elapsed();
    let err = match res {
        Err(e) => e,
        Ok(()) => panic!("shard 1 cannot build, yet the run succeeded"),
    };
    if !matches!(err, netring::Error::Build(_)) {
        eprintln!("skip: the runner failed before its shards ran: {err}");
        return;
    }
    assert!(
        elapsed < Duration::from_secs(3),
        "shard 0 kept running {elapsed:?} after shard 1 failed"
    );
}
