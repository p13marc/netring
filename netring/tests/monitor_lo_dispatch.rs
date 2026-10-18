//! Root-gated end-to-end Monitor test on the loopback interface.
//!
//! Builds a real Monitor on `lo`, generates a few synthetic TCP
//! connect attempts, and asserts that the run loop honours its
//! deadline and the registered handlers fire at least once. Needs
//! `CAP_NET_RAW` on the test binary (i.e. `just setcap` or run as
//! root).
//!
//! Gated on the `integration-tests` Cargo feature — it's a
//! priviledged test, so we don't want it tripping every casual
//! `cargo nextest run` invocation.
//!
//! Run with:
//!
//! ```sh
//! just setcap
//! cargo nextest run -p netring \
//!     --features "tokio,channel,flow,parse,integration-tests" \
//!     -E 'binary(monitor_lo_dispatch)'
//! ```

#![cfg(all(feature = "tokio", feature = "flow", feature = "integration-tests"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::prelude::*;

/// Best-effort traffic generator: spawn a tokio task that opens
/// short-lived TCP connections to `127.0.0.1:9 - reset by peer`
/// in a tight loop while the Monitor runs. Generates
/// `FlowStarted<Tcp>` lifecycle events on the lo capture.
async fn generate_lo_traffic(target: SocketAddr, dur: Duration) {
    let deadline = tokio::time::Instant::now() + dur;
    while tokio::time::Instant::now() < deadline {
        // Attempt a connect; either accepted (port 9, discard) or
        // RST. Both produce a TCP SYN that the AF_PACKET ring sees.
        let _ = tokio::time::timeout(
            Duration::from_millis(20),
            tokio::net::TcpStream::connect(target),
        )
        .await;
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_lo_fires_on_synthetic_traffic() {
    // Bind a listener so the SYN ACK closes cleanly — the AF_PACKET
    // ring still sees the SYN regardless.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral lo socket");
    let target = listener.local_addr().expect("local_addr");

    // Accept and immediately drop incoming connections.
    let accept_task = tokio::spawn(async move { while listener.accept().await.is_ok() {} });

    let starts = Arc::new(AtomicU32::new(0));
    let s = Arc::clone(&starts);

    let monitor_result = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .on::<FlowStarted<Tcp>>(move |_evt: &FlowStarted<Tcp>| {
            s.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build();

    let monitor = match monitor_result {
        Ok(m) => m,
        Err(e) => {
            // CAP_NET_RAW missing (the only realistic build failure
            // shy of a kernel bug). Skip gracefully — the test
            // binary may have been built without setcap.
            eprintln!("Monitor::build failed (likely needs CAP_NET_RAW): {e}");
            accept_task.abort();
            return;
        }
    };

    // Concurrently: generator + run loop. The run_for deadline is
    // the authoritative shutdown signal.
    let dur = Duration::from_millis(500);
    let gen_task = tokio::spawn(generate_lo_traffic(target, dur));

    let run_res = tokio::time::timeout(Duration::from_secs(5), monitor.run_for(dur)).await;
    gen_task.abort();
    accept_task.abort();

    match run_res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("monitor.run_for failed (likely CAP_NET_RAW missing): {e}");
            return;
        }
        Err(_) => panic!("monitor.run_for didn't honour its 500ms deadline within 5s"),
    }

    let fired = starts.load(Ordering::Relaxed);
    assert!(
        fired >= 1,
        "expected at least one FlowStarted<Tcp> from the lo generator, got {fired}"
    );
    eprintln!("monitor_lo_dispatch: handler fired {fired} times");
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_lo_run_until_signal_can_be_aborted() {
    // Confirms the Monitor's tokio::signal::unix wiring doesn't
    // panic when there's no signal installed — we abort via
    // tokio::time::timeout instead.
    let monitor_result = Monitor::builder().interface("lo").protocol::<Tcp>().build();
    let monitor = match monitor_result {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::build failed: {e}");
            return;
        }
    };
    let res = tokio::time::timeout(Duration::from_millis(200), monitor.run_until_signal()).await;
    // Either the timeout elapses (Err) or the capture errors out
    // (Ok(Err(_))). Both are acceptable — the test asserts the
    // run loop is well-formed.
    let _ = res;
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_lo_tick_handler_fires_at_period() {
    // Phase F.2: tick handler firing. Registers a 50ms tick
    // handler, runs the monitor for 600ms, asserts the handler
    // fired at least twice. Doesn't need traffic — the tick
    // pump is independent of the packet stream. (The window is
    // generous: `run_for`'s deadline includes opening the capture,
    // and on a busy host `lo` the drain competes with the ticks.)
    let tick_count = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&tick_count);
    let monitor_result = Monitor::builder()
        .interface("lo")
        .tick(Duration::from_millis(50), move |_t: &Tick| {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build();
    let monitor = match monitor_result {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::build failed: {e}");
            return;
        }
    };
    let res = tokio::time::timeout(
        Duration::from_secs(2),
        monitor.run_for(Duration::from_millis(600)),
    )
    .await;
    match res {
        Ok(Ok(())) => {
            let fired = tick_count.load(Ordering::Relaxed);
            eprintln!("tick handler fired {fired} times in 600ms (period 50ms)");
            assert!(
                fired >= 2,
                "expected tick handler to fire ≥ 2 times across 600ms / 50ms period; got {fired}"
            );
        }
        Ok(Err(e)) => eprintln!("run_for failed (likely no CAP_NET_RAW): {e}"),
        Err(_) => panic!("run_for didn't honour its 600ms deadline within 2s"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_lo_with_two_interfaces_tags_source() {
    // Phase F.1: multi-interface monitor. Opens lo TWICE (the
    // second open is a separate capture on the same iface; both
    // see the same traffic). Verifies that the handler receives
    // distinct `SourceIdx` values for the two captures.
    let starts_per_source: Arc<std::sync::Mutex<[u32; 2]>> =
        Arc::new(std::sync::Mutex::new([0; 2]));
    let s = Arc::clone(&starts_per_source);

    let monitor_result = Monitor::builder()
        .interfaces(["lo", "lo"])
        .protocol::<Tcp>()
        .on_ctx::<FlowStarted<Tcp>>(move |_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            let idx = ctx.source.map_or(usize::MAX, |s| s.0 as usize);
            if idx < 2 {
                s.lock().unwrap()[idx] += 1;
            }
            Ok(())
        })
        .build();
    let monitor = match monitor_result {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::build failed: {e}");
            return;
        }
    };
    let _ = tokio::time::timeout(
        Duration::from_millis(300),
        monitor.run_for(Duration::from_millis(100)),
    )
    .await;
    let counts = *starts_per_source.lock().unwrap();
    eprintln!(
        "monitor_lo_with_two_interfaces: source 0 = {}, source 1 = {}",
        counts[0], counts[1]
    );
    // No hard assertion — with no synthetic traffic, both counts
    // may be 0. The test asserts the build + run path completes
    // without panic.
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_lo_with_layers_and_sink_chain() {
    let monitor_result = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .on_ctx::<FlowStarted<Tcp>>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            let now = ctx.ts;
            let key = evt.key;
            ctx.sink_mut()
                .begin("LoFlow", Severity::Info, now)
                .with_key(&key)
                .emit();
            Ok(())
        })
        .layer(MinSeverity::at_least(Severity::Warning))
        .sink(StdoutSink::with_capacity(1024))
        .build();
    let monitor = match monitor_result {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::build failed: {e}");
            return;
        }
    };
    let _ = tokio::time::timeout(
        Duration::from_millis(300),
        monitor.run_for(Duration::from_millis(100)),
    )
    .await;
}

/// A dummy interface, up and quiet; deleted on drop.
struct QuietDummy(String);

impl QuietDummy {
    fn create() -> Option<Self> {
        let name = format!("nrsrc{}", std::process::id() % 100_000);
        let ip = |args: &[&str]| {
            std::process::Command::new("ip")
                .args(args)
                .status()
                .is_ok_and(|s| s.success())
        };
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &name])
            .output();
        (ip(&["link", "add", &name, "type", "dummy"]) && ip(&["link", "set", &name, "up"]))
            .then(|| Self(name))
    }
}

impl Drop for QuietDummy {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

/// #216: a flow on the second capture interface that no packet ends —
/// ended by the shutdown drain, like an idle sweep — reports that
/// interface: `ctx.source == Some(SourceIdx(1))`. Events no packet drove
/// used to be stamped source 0.
#[tokio::test(flavor = "current_thread")]
async fn flow_ended_by_housekeeping_reports_its_interface() {
    let Some(dummy) = QuietDummy::create() else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let sources: Arc<std::sync::Mutex<Vec<Option<SourceIdx>>>> = Arc::default();
    let s = Arc::clone(&sources);
    let monitor = Monitor::builder()
        .interfaces([dummy.0.as_str(), "lo"])
        .protocol::<Udp>()
        .on_ctx::<FlowEnded<Udp>>(move |e: &FlowEnded<Udp>, ctx: &mut Ctx<'_>| {
            if e.key.a.port() == port || e.key.b.port() == port {
                s.lock().unwrap().push(ctx.source);
            }
            Ok(())
        })
        .build()
        .expect("build");
    let health = monitor.health();
    let sender = std::thread::spawn(move || {
        // Once the capture sockets are open.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !health.is_ready() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..5 {
            let _ = sock.send_to(b"netring-source", ("127.0.0.1", port));
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let res = monitor.run_for(Duration::from_millis(1200)).await;
    sender.join().unwrap();
    if let Err(e) = res {
        eprintln!("skip: run failed (needs CAP_NET_RAW): {e}");
        return;
    }
    let sources = sources.lock().unwrap();
    assert!(!sources.is_empty(), "the flow ended at shutdown");
    assert!(
        sources.iter().all(|s| *s == Some(SourceIdx(1))),
        "{sources:?}"
    );
}
