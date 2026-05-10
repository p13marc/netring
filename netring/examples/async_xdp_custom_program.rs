//! AF_XDP capture using a caller-loaded XDP program.
//!
//! Demonstrates `XdpSocketBuilder::with_program(prog)` — the escape
//! hatch for users who've compiled their own XDP program (via
//! `aya-bpf` + `bpf-linker`, or `clang -target bpf`) and want netring
//! to handle the kernel attach + AF_XDP socket registration.
//!
//! For the simple case (built-in `bpf_redirect_map(...)` redirect-all
//! program), prefer
//! [`async_xdp_self_loaded`](./async_xdp_self_loaded.rs) +
//! `with_default_program()`.
//!
//! Your program must:
//! 1. Define a `BPF_MAP_TYPE_XSKMAP` (any name).
//! 2. Call `bpf_redirect_map(&xsks_map, ctx->rx_queue_index, ...)`.
//!
//! This example walks through the API shape but does not ship a
//! compiled program of its own — point `MY_BYTECODE_PATH` at one of
//! yours.
//!
//! Requires CAP_NET_RAW + CAP_BPF + CAP_NET_ADMIN. Use `just setcap`.
//!
//! Usage:
//!     cargo run --example async_xdp_custom_program \
//!         --features tokio,af-xdp,xdp-loader -- [iface] [bytecode_path]

#[cfg(all(feature = "tokio", feature = "af-xdp", feature = "xdp-loader"))]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use aya::Ebpf;
    use netring::XdpSocket;
    use netring::xdp::{XdpFlags, XdpProgram};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let bytecode_path = match std::env::args().nth(2) {
        Some(p) => p,
        None => {
            eprintln!(
                "no bytecode_path provided. \
                 Pass a compiled XDP program (.o) as the second arg."
            );
            return Ok(());
        }
    };

    eprintln!("loading {bytecode_path} via aya, attaching to {iface}");
    let bytes = std::fs::read(&bytecode_path)
        .map_err(|e| netring::Error::Config(format!("read bytecode: {e}")))?;
    let bpf = Ebpf::load(&bytes)
        .map_err(|e| netring::Error::Config(format!("aya load: {e}")))?;

    // Adjust these to match the symbol names in your bytecode.
    let prog_name = std::env::var("XDP_PROG_NAME").unwrap_or_else(|_| "xdp_sock_prog".into());
    let map_name = std::env::var("XDP_MAP_NAME").unwrap_or_else(|_| "xsks_map".into());
    let prog = XdpProgram::from_aya(bpf, &prog_name, &map_name);

    let mut sock = XdpSocket::builder()
        .interface(&iface)
        .queue_id(0)
        .frame_size(2048)
        .frame_count(4096)
        .with_program(prog) //  ← plan 12 phase 2: bring your own program
        .xdp_attach_flags(XdpFlags::SKB_MODE)
        .force_replace(true)
        .build()?;

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut packets: u64 = 0;

    while Instant::now() < deadline {
        let batch = sock.recv()?;
        for _pkt in &batch {
            packets += 1;
        }
        if batch.is_empty() {
            tokio::time::sleep(Duration::from_micros(200)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    eprintln!("captured {packets} packets — program will detach on Drop");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "af-xdp", feature = "xdp-loader")))]
fn main() {
    eprintln!("Build with --features tokio,af-xdp,xdp-loader");
}
