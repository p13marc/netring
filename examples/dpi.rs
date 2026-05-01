//! Simple Deep Packet Inspection (DPI) example.
//!
//! Captures packets and performs protocol analysis using `etherparse`:
//! - Decodes Ethernet → VLAN → IPv4/IPv6 → TCP/UDP/ICMP headers
//! - Detects HTTP, TLS, DNS, SSH by port and payload signatures
//! - Prints a color-coded summary per packet
//!
//! Usage: cargo run --example dpi -- [interface]
//! Requires CAP_NET_RAW.

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use netring::{CaptureBuilder, PacketSource};
use std::time::{Duration, Instant};

fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("🔍 DPI capture on {iface} (Ctrl-C to stop)\n");

    let mut rx = CaptureBuilder::default()
        .interface(&iface)
        .block_timeout_ms(50)
        .ignore_outgoing(false)
        .build()?;

    let start = Instant::now();
    let mut stats = DpiStats::default();

    loop {
        let Some(batch) = rx.next_batch_blocking(Duration::from_millis(200))? else {
            continue;
        };

        for pkt in &batch {
            stats.total += 1;
            stats.bytes += pkt.len() as u64;

            let data = pkt.data();
            let ts = pkt.timestamp();

            match SlicedPacket::from_ethernet(data) {
                Ok(parsed) => {
                    let (src_ip, dst_ip) = format_ips(&parsed);
                    let (proto, src_port, dst_port, payload) = format_transport(&parsed);
                    let app = detect_application(src_port, dst_port, payload);

                    // Track protocol stats
                    match proto {
                        "TCP" => stats.tcp += 1,
                        "UDP" => stats.udp += 1,
                        "ICMP" | "ICMPv6" => stats.icmp += 1,
                        _ => stats.other += 1,
                    }

                    println!(
                        "[{}.{:03}] {src_ip} → {dst_ip} | {proto}/{} | {:<5} | {} bytes{}",
                        ts.sec,
                        ts.nsec / 1_000_000,
                        format_ports(src_port, dst_port),
                        app,
                        pkt.len(),
                        format_payload_peek(payload),
                    );
                }
                Err(_) => {
                    stats.unparseable += 1;
                    println!(
                        "[{}.{:03}] ??? | unparseable | {} bytes",
                        ts.sec,
                        ts.nsec / 1_000_000,
                        pkt.len()
                    );
                }
            }
        }

        // Print summary every 5 seconds
        if start.elapsed().as_secs() > 0 && stats.total % 100 == 0 {
            eprintln!("\n--- {stats} ---\n");
        }
    }
}

fn format_ips(parsed: &SlicedPacket) -> (String, String) {
    match &parsed.net {
        Some(NetSlice::Ipv4(ip)) => (
            format!("{}", ip.header().source_addr()),
            format!("{}", ip.header().destination_addr()),
        ),
        Some(NetSlice::Ipv6(ip)) => (
            format!("{}", ip.header().source_addr()),
            format!("{}", ip.header().destination_addr()),
        ),
        None => ("--".into(), "--".into()),
    }
}

fn format_transport<'a>(parsed: &'a SlicedPacket<'a>) -> (&'static str, u16, u16, &'a [u8]) {
    match &parsed.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            "TCP",
            tcp.source_port(),
            tcp.destination_port(),
            tcp.payload(),
        ),
        Some(TransportSlice::Udp(udp)) => (
            "UDP",
            udp.source_port(),
            udp.destination_port(),
            udp.payload(),
        ),
        Some(TransportSlice::Icmpv4(icmp)) => ("ICMP", 0, 0, icmp.payload()),
        Some(TransportSlice::Icmpv6(icmp)) => ("ICMPv6", 0, 0, icmp.payload()),
        None => {
            let payload = parsed.ip_payload().map(|p| p.payload).unwrap_or(&[]);
            ("???", 0, 0, payload)
        }
    }
}

fn format_ports(src: u16, dst: u16) -> String {
    if src == 0 && dst == 0 {
        "--".into()
    } else {
        format!("{src}→{dst}")
    }
}

/// Simple application-layer protocol detection by port + payload signature.
fn detect_application(src_port: u16, dst_port: u16, payload: &[u8]) -> &'static str {
    // Check well-known ports
    let port = dst_port.min(src_port);
    match port {
        53 => return "DNS",
        22 => return "SSH",
        443 | 8443 => {
            // TLS ClientHello starts with 0x16 0x03
            if payload.len() >= 2 && payload[0] == 0x16 && payload[1] == 0x03 {
                return "TLS";
            }
            return "HTTPS";
        }
        80 | 8080 => {
            if is_http(payload) {
                return "HTTP";
            }
            return "HTTP?";
        }
        _ => {}
    }

    // Payload-based detection for non-standard ports
    if is_http(payload) {
        return "HTTP";
    }
    if payload.len() >= 2 && payload[0] == 0x16 && payload[1] == 0x03 {
        return "TLS";
    }
    if payload.len() >= 12 && (payload[2] & 0x80) != 0 {
        // DNS response flag heuristic
        if dst_port == 53 || src_port == 53 {
            return "DNS";
        }
    }
    if payload.starts_with(b"SSH-") {
        return "SSH";
    }

    if payload.is_empty() {
        return "--";
    }
    "???"
}

fn is_http(payload: &[u8]) -> bool {
    payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"PUT ")
        || payload.starts_with(b"DELETE ")
        || payload.starts_with(b"HEAD ")
        || payload.starts_with(b"HTTP/")
        || payload.starts_with(b"PATCH ")
}

fn format_payload_peek(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let preview_len = payload.len().min(40);
    let preview = &payload[..preview_len];

    // If mostly printable ASCII, show as text
    let printable = preview
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    if printable > preview_len / 2 {
        let s: String = preview
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        format!(" | {s}")
    } else {
        let hex: String = preview
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(" | {hex}")
    }
}

#[derive(Default)]
struct DpiStats {
    total: u64,
    bytes: u64,
    tcp: u64,
    udp: u64,
    icmp: u64,
    other: u64,
    unparseable: u64,
}

impl std::fmt::Display for DpiStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} pkts ({} bytes) | TCP:{} UDP:{} ICMP:{} other:{} bad:{}",
            self.total, self.bytes, self.tcp, self.udp, self.icmp, self.other, self.unparseable
        )
    }
}
