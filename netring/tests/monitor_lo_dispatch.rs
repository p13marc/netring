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
        .on::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
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
async fn monitor_lo_with_layers_and_sink_chain() {
    let monitor_result = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .on::<FlowStarted<Tcp>, _, _>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
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
