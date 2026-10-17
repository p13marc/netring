//! Live run-loop regressions on `lo` (0.31.2 audit): the handler error
//! policy on capture-stats handlers, idle stop with a tick handler,
//! timers under sustained load.
//!
//! Need `CAP_NET_RAW` (run as root); without it the monitor can't open
//! `lo` and each test returns early, like the other `monitor_lo_*`
//! tests. The timing tests capture on the `lo` of a scratch network
//! namespace (`ip netns add`, root only) so traffic from anything else
//! on the host can't disturb them.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use netring::monitor::{Backend, HandlerErrorPolicy, Monitor};
use netring::netns::NetNs;
use netring::protocol::builtin::Udp;

/// A fresh network namespace with `lo` up and nothing else in it,
/// deleted on drop. `None` without the privileges to create one.
struct ScratchNetns {
    name: String,
    ns: Arc<NetNs>,
}

impl ScratchNetns {
    fn create(tag: &str) -> Option<Self> {
        let name = format!("nrm-{tag}-{}", std::process::id());
        let _ = Command::new("ip").args(["netns", "del", &name]).output();
        let ok = |args: &[&str]| {
            Command::new("ip")
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !ok(&["netns", "add", &name]) {
            eprintln!("skipping: `ip netns add` failed (needs root)");
            return None;
        }
        let guard = Self {
            ns: Arc::new(NetNs::from_name(&name).ok()?),
            name,
        };
        if !ok(&["-n", &guard.name, "link", "set", "lo", "up"]) {
            return None;
        }
        Some(guard)
    }
}

impl Drop for ScratchNetns {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .output();
    }
}

/// `HandlerErrorPolicy::Isolate` covers `on_capture_stats` handlers: an
/// `Err` is counted and the monitor keeps running (it used to stop).
#[tokio::test(flavor = "current_thread")]
async fn isolate_policy_covers_capture_stats_handlers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let monitor = Monitor::builder()
        .interface("lo")
        .protocol::<Udp>()
        .drain_timeout(Duration::ZERO)
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .on_capture_stats(Duration::from_millis(50), move |_t, _ctx| {
            c.fetch_add(1, Ordering::SeqCst);
            Err(netring::Error::Config("stats handler failed".into()))
        })
        .build()
        .unwrap();
    let health = monitor.health();
    if let Err(e) = monitor.run_for(Duration::from_millis(400)).await {
        if calls.load(Ordering::SeqCst) == 0 {
            eprintln!("run_for errored before any sample (likely no CAP_NET_RAW): {e}");
            return;
        }
        panic!("Isolate must keep the monitor running: {e}");
    }
    let n = calls.load(Ordering::SeqCst);
    assert!(n >= 3, "sampled every 50 ms for 400 ms: {n}");
    assert_eq!(health.handler_errors(), n as u64);
}

/// `run_until_idle(window)` stops after `window` without traffic even
/// when a tick handler fires more often than that: a tick is not
/// traffic (it used to reset the idle timer, so the monitor never
/// stopped).
#[tokio::test(flavor = "current_thread")]
async fn run_until_idle_stops_despite_a_faster_tick() {
    let Some(scratch) = ScratchNetns::create("idle") else {
        return;
    };
    let ticks = Arc::new(AtomicUsize::new(0));
    let t = Arc::clone(&ticks);
    let monitor = Monitor::builder()
        .capture_in_netns("lo", Backend::af_packet(), Arc::clone(&scratch.ns))
        .protocol::<Udp>()
        .drain_timeout(Duration::ZERO)
        .tick_ctx(
            Duration::from_millis(50),
            move |_ctx: &mut netring::ctx::Ctx<'_>| {
                t.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .build()
        .unwrap();
    let window = Duration::from_millis(300);
    let start = Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(5), monitor.run_until_idle(window)).await;
    let elapsed = start.elapsed();
    res.expect("the monitor went idle").unwrap();
    assert!(elapsed >= window, "stopped early: {elapsed:?}");
    assert!(ticks.load(Ordering::SeqCst) >= 3, "the tick ran meanwhile");
}

/// Under sustained load — the capture is readable every time the loop
/// looks, because packets arrive faster than the handlers process them
/// — ticks keep firing and `run_for` still stops on time. The capture
/// branch used to win every `select!` and drain until the ring was
/// empty, which it never was: ticks, sweeps, telemetry and the deadline
/// all starved until the traffic stopped.
#[tokio::test(flavor = "current_thread")]
async fn ticks_and_deadline_are_not_starved_by_a_busy_capture() {
    use netring::monitor::subscription::packet;
    let Some(scratch) = ScratchNetns::create("busy") else {
        return;
    };
    // Senders inside the namespace, flooding its `lo` for 4 s.
    let flood_for = Duration::from_secs(4);
    let senders: Vec<_> = (0..2)
        .map(|_| {
            let sock = scratch
                .ns
                .run_in(|| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap();
            std::thread::spawn(move || {
                let until = Instant::now() + flood_for;
                while Instant::now() < until {
                    for _ in 0..256 {
                        let _ = sock.send_to(b"0123456789abcdef", "127.0.0.1:9");
                    }
                }
            })
        })
        .collect();
    let ticks = Arc::new(AtomicUsize::new(0));
    let t = Arc::clone(&ticks);
    let monitor = Monitor::builder()
        .capture_in_netns("lo", Backend::af_packet(), Arc::clone(&scratch.ns))
        .drain_timeout(Duration::ZERO)
        // ~5 µs per packet: slower than the flood arrives.
        .subscribe(packet().udp().to(|_view, _ctx| {
            let spin = Instant::now();
            while spin.elapsed() < Duration::from_micros(5) {}
            Ok(())
        }))
        .tick_ctx(
            Duration::from_millis(50),
            move |_ctx: &mut netring::ctx::Ctx<'_>| {
                t.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .build()
        .unwrap();
    let start = Instant::now();
    monitor.run_for(Duration::from_secs(2)).await.unwrap();
    let elapsed = start.elapsed();
    for s in senders {
        s.join().unwrap();
    }
    eprintln!(
        "run_for(2 s) took {elapsed:?}, {} ticks",
        ticks.load(Ordering::SeqCst)
    );
    assert!(
        elapsed < Duration::from_millis(3_000),
        "run_for(2 s) overran: {elapsed:?}"
    );
    let n = ticks.load(Ordering::SeqCst);
    assert!(n >= 5, "50 ms ticks over 2 s of load: {n}");
}

/// A `ShardedRunner` shard that fails stops its siblings, so
/// `run_until_signal` returns the error instead of running the healthy
/// shards until a signal arrives (the shared stop flag was never set).
#[test]
fn a_failing_shard_stops_its_siblings() {
    use netring::config::FanoutMode;
    use netring::monitor::shard::ShardedRunner;
    let group = (std::process::id() as u16).wrapping_mul(31) | 1;
    let runner = ShardedRunner::new("lo", FanoutMode::Hash, group, 2, move |shard| {
        if shard == 1 {
            return Err(netring::Error::Config("shard 1 failed".into()));
        }
        Monitor::builder()
            .interface("lo")
            .fanout(FanoutMode::Hash, group)
            .protocol::<Udp>()
            .drain_timeout(Duration::ZERO)
            .build()
    });
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(runner.run_until_signal());
    });
    let res = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the healthy shard stopped with its failed sibling");
    let err = res.expect_err("the failed shard's error").to_string();
    // Without CAP_NET_RAW shard 0 fails to open `lo` too; either way the
    // runner returns an error, promptly.
    assert!(
        err.contains("shard 1 failed") || err.contains("privileges"),
        "{err}"
    );
}
