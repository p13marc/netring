//! Synthetic traffic generator — paired with the L7 / anomaly
//! examples so you can demo them on `lo` without real traffic and
//! **without root / `CAP_NET_RAW`**.
//!
//! Companion to:
//! - `examples/l7/{multi_protocol_monitor, http_session, dns_lookups, full_monitor}`
//! - `examples/anomaly/{dns_query_burst, dns_resolved_no_connection,
//!   slow_tls_handshake, lateral_movement, icmp_explained_drop,
//!   anomaly_monitor_demo}`
//!
//! Run this in one terminal, run the example you want to demo in
//! another. Both target `lo` by default. Userspace sockets only —
//! the OS kernel turns them into real packets on the wire which
//! the netring captures pick up.
//!
//! What it emits:
//!
//! - **DNS-ish queries** to `127.0.0.1:53` — UDP packets containing
//!   a syntactically valid DNS query message. The `dns_query_burst`
//!   detector fires at ~50 queries / 10s; the default schedule
//!   below pushes ~120 in 10s from one source IP, well above the
//!   threshold.
//! - **TCP SYN→RST flows** — `connect()` to `127.0.0.1:9` (the
//!   discard port, normally closed) generates a SYN that the kernel
//!   answers with RST. Each one is a single short-lived flow ending
//!   in `EndReason::Rst` — perfect for `icmp_explained_drop`'s
//!   "unexplained" arm (no preceding ICMP error).
//! - **HTTP-shaped requests** — connects to `127.0.0.1:8080`, sends
//!   a literal `GET / HTTP/1.1\r\n...` line, then closes. The
//!   server-side connect will fail (no listener) but the SYN/RST
//!   exchange gives `multi_protocol_monitor` a TCP flow to count
//!   and lets you sanity-check the BPF filter on port 8080.
//! - **Fan-out** — a final phase opens 15 short-lived TCP flows to
//!   distinct `127.0.0.X` destinations from one source, large
//!   enough to trip `lateral_movement` (threshold 10 by default).
//!
//! What it does NOT emit:
//!
//! - **ICMP errors with `IcmpInner`** — real ICMP error generation
//!   needs `CAP_NET_ADMIN` and raw sockets. The
//!   `icmp_explained_drop` example will only see the "unexplained"
//!   arm from this generator. To see the "explained" arm, point a
//!   real client at an unroutable destination (e.g. `nc -u
//!   192.0.2.99 9999`) so the upstream router returns a real ICMP
//!   error.
//! - **Real TLS ClientHello bytes** — the `slow_tls_handshake`
//!   example needs a parseable TLS ClientHello, which is too
//!   involved for a userspace demo. Use `curl https://...` instead.
//!
//! Usage:
//!     cargo run -p netring --example synthetic_traffic \
//!         --features tokio -- [seconds]
//!
//! Defaults: runs for 30 seconds.

#[cfg(feature = "tokio")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::time::{sleep, timeout};

    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!(
        "[synthetic] driving lo with DNS + TCP + HTTP + fan-out for {seconds}s\n\
         (no root / CAP_NET_RAW needed — userspace sockets only)"
    );

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut tick = 0u64;

    while Instant::now() < deadline {
        tick += 1;

        // ── Phase 1: DNS burst (~10/s from one src) ─────────────
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        for i in 0..10 {
            let pkt = fake_dns_query(0x1000 + tick as u16 + i, &format!("h{i}.test"));
            let _ = udp.send_to(&pkt, "127.0.0.1:53").await;
        }
        drop(udp);

        // ── Phase 2: TCP SYN→RST (closed port) ──────────────────
        for port in [9u16, 8080] {
            let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let _ = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await;
        }

        // ── Phase 3: HTTP-shaped request (will RST; just for the
        //              tcp_session BPF on port 8080) ──────────────
        if let Ok(Ok(mut s)) = timeout(
            Duration::from_millis(100),
            TcpStream::connect("127.0.0.1:8080"),
        )
        .await
        {
            let _ = s
                .write_all(
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: netring-synthetic\r\n\r\n",
                )
                .await;
            drop(s);
        }

        // ── Phase 4: lateral-movement fan-out (one src → 15 dst) ─
        // 127.0.0.0/8 is all-loopback so all of these are
        // "internal" by the rule's RFC 1918 + loopback check.
        if tick.is_multiple_of(5) {
            for i in 0..15u8 {
                let dst: SocketAddr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10 + i)), 9);
                let _ = timeout(Duration::from_millis(50), TcpStream::connect(dst)).await;
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    eprintln!("[synthetic] done. {tick} ticks generated.");
    Ok(())
}

/// Minimal DNS query packet — 12-byte header + one QNAME + qtype +
/// qclass. Enough that flowscope's `DnsUdpParser` decodes it.
#[cfg(feature = "tokio")]
fn fake_dns_query(txid: u16, qname: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(48);
    pkt.extend_from_slice(&txid.to_be_bytes()); // transaction id
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ancount
    pkt.extend_from_slice(&0u16.to_be_bytes()); // nscount
    pkt.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // QNAME — length-prefixed labels, root-terminated.
    for label in qname.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qtype = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qclass = IN
    pkt
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("Build with --features tokio");
}
