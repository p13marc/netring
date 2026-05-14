//! Async transparent bridge between two interfaces with Ctrl-C shutdown.
//!
//! Demonstrates [`Bridge::run_async`] — the tokio-runtime variant that uses
//! [`AsyncFd`](tokio::io::unix::AsyncFd) instead of synchronous `poll(2)`.
//! Both sides of the bridge are driven by the same reactor as the rest of
//! your tokio program.
//!
//! Usage: cargo run --example async_bridge --features tokio -- <iface_a> <iface_b>

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::bridge::{Bridge, BridgeAction, BridgeDirection};

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <iface_a> <iface_b>", args[0]);
        eprintln!("Example: {} eth0 eth1", args[0]);
        std::process::exit(1);
    }
    let iface_a = &args[1];
    let iface_b = &args[2];

    eprintln!("Async-bridging {iface_a} ↔ {iface_b} (Ctrl-C to stop)");

    let mut bridge = Bridge::builder()
        .interface_a(iface_a)
        .interface_b(iface_b)
        .build()?;

    let mut a_to_b = 0u64;
    let mut b_to_a = 0u64;

    // The bridge owns its filter closure for the duration of the run.
    // To support graceful shutdown we race run_async against ctrl_c via
    // tokio::select! — when SIGINT lands, we drop the run_async future
    // (cancel-safe; just drops the AsyncFd registrations) and break out.
    let run = bridge.run_async(|_pkt, dir| {
        match dir {
            BridgeDirection::AtoB => a_to_b += 1,
            BridgeDirection::BtoA => b_to_a += 1,
        }
        if (a_to_b + b_to_a).is_multiple_of(1000) {
            eprintln!("A→B: {a_to_b}  B→A: {b_to_a}");
        }
        BridgeAction::Forward
    });

    tokio::select! {
        result = run => {
            // run_async returns only on I/O error
            if let Err(e) = result {
                eprintln!("bridge error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\nSIGINT — shutting bridge down");
        }
    }

    let stats = bridge.cumulative_stats()?;
    eprintln!("Final: {stats}");
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!(
        "This example requires the 'tokio' feature: cargo run --example async_bridge --features tokio"
    );
}
