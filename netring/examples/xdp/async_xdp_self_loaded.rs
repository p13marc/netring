//! AF_XDP capture from zero — the loader takes care of attaching the
//! XDP program to the interface.
//!
//! Demonstrates `XdpSocketBuilder::with_default_program()` (plan 12).
//! Without this, you'd need to load and attach an XDP program via
//! `aya`, `libxdp`, or `bpftool` separately. With it, the call below
//! is a complete recipe.
//!
//! Requires CAP_NET_RAW + CAP_BPF + CAP_NET_ADMIN. Use `just setcap`.
//!
//! Default attach mode is SKB (works on `lo` and every other
//! interface). Pass DRV mode if your NIC supports native XDP:
//!
//!     XDP_FLAGS=DRV cargo run --example async_xdp_self_loaded \
//!         --features tokio,af-xdp,xdp-loader -- eth0
//!
//! Usage:
//!     cargo run --example async_xdp_self_loaded \
//!         --features tokio,af-xdp,xdp-loader -- [iface] [seconds]

#[cfg(all(feature = "tokio", feature = "af-xdp", feature = "xdp-loader"))]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::XdpSocket;
    use netring::xdp::XdpFlags;
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let flags = match std::env::var("XDP_FLAGS").as_deref() {
        Ok("DRV") => XdpFlags::DRV_MODE,
        Ok("HW") => XdpFlags::HW_MODE,
        _ => XdpFlags::SKB_MODE,
    };

    eprintln!(
        "AF_XDP RX on {iface} for {seconds}s (mode={flags:?}); \
         loading built-in redirect-all XDP program"
    );

    let mut sock = XdpSocket::builder()
        .interface(&iface)
        .queue_id(0)
        .frame_size(2048)
        .frame_count(4096)
        .with_default_program() //  ← plan 12: load+attach+register
        .xdp_attach_flags(flags)
        .force_replace(true) // robust to leftover programs from prior runs
        .build()?;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut packets: u64 = 0;
    let mut bytes: u64 = 0;

    while Instant::now() < deadline {
        let batch = sock.recv()?;
        for pkt in &batch {
            packets += 1;
            bytes += pkt.data.len() as u64;
        }
        if batch.is_empty() {
            tokio::time::sleep(Duration::from_micros(200)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    eprintln!(
        "captured {packets} packets / {bytes} bytes in {seconds}s — \
         program will detach on Drop"
    );
    drop(sock);
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "af-xdp", feature = "xdp-loader")))]
fn main() {
    eprintln!("Build with --features tokio,af-xdp,xdp-loader");
}
