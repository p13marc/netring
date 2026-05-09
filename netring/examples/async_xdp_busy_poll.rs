//! AF_XDP RX with the full busy-poll trio for low-latency capture.
//!
//! Demonstrates kernel ≥ 5.11 socket options that close most of the
//! latency gap between AF_XDP and DPDK:
//!
//! - `SO_BUSY_POLL`        — busy-poll timeout (microseconds)
//! - `SO_PREFER_BUSY_POLL` — prefer busy-polling over softirq scheduling
//! - `SO_BUSY_POLL_BUDGET` — cap per-poll packet count
//!
//! Reference: <https://docs.kernel.org/networking/af_xdp.html>
//!
//! NOTE: This example needs an XDP program already attached to the
//! interface that redirects packets into the AF_XDP socket. See
//! plan 12 in `plans/12-xdp-loader.md` for the upcoming built-in
//! loader. Until then, attach one externally (e.g. via `aya` or
//! `xdp-loader`).
//!
//! Usage:
//!     just setcap   # once, to grant CAP_NET_RAW
//!     cargo run --example async_xdp_busy_poll --features tokio,af-xdp -- [iface] [seconds]

#[cfg(all(feature = "tokio", feature = "af-xdp"))]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::XdpSocket;
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!(
        "AF_XDP RX on {iface} for {seconds}s with busy-poll trio: \
         busy_poll_us=50, prefer_busy_poll=true, busy_poll_budget=64"
    );

    let mut sock = XdpSocket::builder()
        .interface(&iface)
        .queue_id(0)
        .frame_size(2048)
        .frame_count(4096)
        .busy_poll_us(50) //  ← SO_BUSY_POLL (kernel ≥ 4.5)
        .prefer_busy_poll(true) //  ← SO_PREFER_BUSY_POLL (kernel ≥ 5.11)
        .busy_poll_budget(64) //  ← SO_BUSY_POLL_BUDGET (kernel ≥ 5.11)
        .build()?;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut packets: u64 = 0;
    let mut bytes: u64 = 0;

    while Instant::now() < deadline {
        // Drive the RX ring. With busy-poll active the kernel keeps
        // the NAPI loop hot, so this returns quickly.
        let batch = sock.recv()?;
        for pkt in &batch {
            packets += 1;
            bytes += pkt.data.len() as u64;
        }
        // Yield briefly so we don't pin the executor thread purely
        // on the AF_XDP poll loop.
        if batch.is_empty() {
            tokio::time::sleep(Duration::from_micros(100)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    let pps = packets as f64 / seconds as f64;
    let bps = bytes as f64 * 8.0 / seconds as f64;
    eprintln!(
        "RX summary: {packets} packets ({bytes} B) in {seconds}s — \
         {pps:.0} pps / {bps:.2} bps"
    );

    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "af-xdp")))]
fn main() {
    eprintln!("Build with --features tokio,af-xdp");
}
