//! 0.21 F: `monitor.subscribe::<P>()` streaming consumer demo.
//!
//! Subscribes to HTTP messages parsed off the monitor's run loop
//! and prints them from a separate tokio task. Both the
//! subscriber AND any registered `.on::<Http>` handler see every
//! message — the broadcast slot fans out per subscriber clone.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_stream_consumer \
//!     --features "tokio,flow,http" -- eth0
//! ```
//!
//! Then in another shell: `curl http://example.com` or similar
//! over the watched interface.

use std::time::Duration;

use netring::monitor::Monitor;
use netring::protocol::builtin::Http;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let monitor = Monitor::builder()
        .interface(&iface)
        // `with_broadcast::<Http>` registers Http as a broadcast
        // slot — exactly the spot where `subscribe::<Http>()`
        // pulls subscriber clones from. Calling `.protocol::<Http>()`
        // instead would install a regular slot and `subscribe`
        // would error with `BuildError::ProtocolNotBroadcast`.
        .with_broadcast::<Http>()
        .name("stream-consumer-demo")
        .build()?;

    // Mint a subscriber BEFORE the monitor moves into `run_for`.
    let mut http_stream = monitor.subscribe::<Http>()?;

    eprintln!(
        "[stream-consumer] watching {iface} for 60s; \
         HTTP messages will print as `[stream] <msg>` from the consumer task"
    );

    // Consumer task — independent of the run loop. Polls every
    // 100ms; bounded drain via `recv_many(buf, 32)` prevents
    // queue growth from monopolizing one tick.
    let consumer = tokio::task::spawn_local(async move {
        let mut buf = Vec::new();
        let mut total = 0u64;
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let n = http_stream.recv_many(&mut buf, 32);
            for msg in buf.drain(..) {
                total += 1;
                println!("[stream] http #{total}: {msg:?}");
            }
            if n == 0 && http_stream.subscribers() == 1 {
                // Only the dispatcher's clone left → monitor is
                // gone; consumer can exit.
                break;
            }
        }
        eprintln!("[stream-consumer] consumer drained {total} messages");
    });

    monitor.run_for(Duration::from_secs(60)).await?;

    // Wait briefly for the consumer to drain any final messages.
    let _ = tokio::time::timeout(Duration::from_secs(2), consumer).await;
    Ok(())
}
