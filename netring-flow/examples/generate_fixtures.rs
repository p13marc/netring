//! Generate the pcap fixtures committed to `tests/data/`.
//!
//! Run with:
//!     cargo run -p netring-flow --example generate_fixtures --features test-helpers
//!
//! Writes:
//!     netring-flow/tests/data/http_session.pcap
//!     netring-flow/tests/data/dns_queries.pcap
//!     netring-flow/tests/data/mixed_short.pcap
//!
//! The fixtures are deterministic — running the example again
//! produces byte-identical files. Re-run only when you want to
//! change the synthetic traffic shape.

use std::fs::{File, create_dir_all};
use std::io::BufWriter;
use std::time::Duration;

use netring_flow::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use pcap_file::DataLink;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::path::Path::new("netring-flow/tests/data");
    create_dir_all(dir)?;

    write_http_session(&dir.join("http_session.pcap"))?;
    write_dns_queries(&dir.join("dns_queries.pcap"))?;
    write_mixed_short(&dir.join("mixed_short.pcap"))?;

    eprintln!("✓ wrote fixtures into {}/", dir.display());
    Ok(())
}

fn pcap_writer<W: std::io::Write>(w: W) -> Result<PcapWriter<W>, Box<dyn std::error::Error>> {
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::MicroSecond,
        endianness: pcap_file::Endianness::native(),
    };
    Ok(PcapWriter::with_header(w, header)?)
}

/// Write a packet at the given monotonic timestamp.
fn write(
    pw: &mut PcapWriter<impl std::io::Write>,
    ts: Duration,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    pw.write_packet(&PcapPacket {
        timestamp: ts,
        orig_len: data.len() as u32,
        data: data.into(),
    })?;
    Ok(())
}

/// Build a synthetic HTTP/1.1 session over IPv4/TCP. ~10 packets.
fn write_http_session(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut pw = pcap_writer(BufWriter::new(File::create(path)?))?;

    let client_ip = [10, 0, 0, 1];
    let server_ip = [10, 0, 0, 2];
    let mac_c = [0x02, 0, 0, 0, 0, 1];
    let mac_s = [0x02, 0, 0, 0, 0, 2];
    let cport = 54_321u16;
    let sport = 80u16;

    // Sequence numbers
    let mut c_seq = 1_000u32;
    let mut s_seq = 5_000u32;

    let mut t = Duration::from_micros(0);
    let dt = Duration::from_micros(50);

    // 1. SYN c->s
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_c, mac_s, client_ip, server_ip, cport, sport, c_seq, 0, 0x02, b"",
        ),
    )?;
    t += dt;
    c_seq = c_seq.wrapping_add(1);

    // 2. SYN-ACK s->c
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_s, mac_c, server_ip, client_ip, sport, cport, s_seq, c_seq, 0x12, b"",
        ),
    )?;
    t += dt;
    s_seq = s_seq.wrapping_add(1);

    // 3. ACK c->s (3WHS done)
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_c, mac_s, client_ip, server_ip, cport, sport, c_seq, s_seq, 0x10, b"",
        ),
    )?;
    t += dt;

    // 4. GET request c->s
    let req =
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netring-test/0.7\r\n\r\n";
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_c, mac_s, client_ip, server_ip, cport, sport, c_seq, s_seq, 0x18, req,
        ),
    )?;
    t += dt;
    c_seq = c_seq.wrapping_add(req.len() as u32);

    // 5. ACK s->c
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_s, mac_c, server_ip, client_ip, sport, cport, s_seq, c_seq, 0x10, b"",
        ),
    )?;
    t += dt;

    // 6. 200 OK response s->c
    let resp =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!";
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_s, mac_c, server_ip, client_ip, sport, cport, s_seq, c_seq, 0x18, resp,
        ),
    )?;
    t += dt;
    s_seq = s_seq.wrapping_add(resp.len() as u32);

    // 7. ACK c->s
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_c, mac_s, client_ip, server_ip, cport, sport, c_seq, s_seq, 0x10, b"",
        ),
    )?;
    t += dt;

    // 8. FIN c->s
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_c, mac_s, client_ip, server_ip, cport, sport, c_seq, s_seq, 0x11, b"",
        ),
    )?;
    t += dt;
    c_seq = c_seq.wrapping_add(1);

    // 9. FIN-ACK s->c
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_s, mac_c, server_ip, client_ip, sport, cport, s_seq, c_seq, 0x11, b"",
        ),
    )?;
    t += dt;
    s_seq = s_seq.wrapping_add(1);

    // 10. ACK c->s (graceful close)
    write(
        &mut pw,
        t,
        &ipv4_tcp(
            mac_c, mac_s, client_ip, server_ip, cport, sport, c_seq, s_seq, 0x10, b"",
        ),
    )?;

    Ok(())
}

/// Synthetic DNS query/response pairs.
fn write_dns_queries(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut pw = pcap_writer(BufWriter::new(File::create(path)?))?;

    let client_ip = [192, 168, 1, 100];
    let resolver_ip = [192, 168, 1, 1];

    let mut t = Duration::from_micros(0);
    let dt = Duration::from_micros(100);

    // We don't have a DNS message builder, so we hand-craft minimal
    // valid DNS payloads.
    let q_a_example = build_dns_a_query(0x1234, "example.com");
    let r_a_example = build_dns_a_response(0x1234, "example.com", [93, 184, 216, 34]);
    let q_a_other = build_dns_a_query(0x5678, "rust-lang.org");
    let r_nxdomain = build_dns_nxdomain(0x9abc, "does-not-exist.invalid");

    let cport = 53_300u16;
    let sport = 53u16;

    // Pair 1: example.com → A record
    write(
        &mut pw,
        t,
        &ipv4_udp(client_ip, resolver_ip, cport, sport, &q_a_example),
    )?;
    t += dt;
    write(
        &mut pw,
        t,
        &ipv4_udp(resolver_ip, client_ip, sport, cport, &r_a_example),
    )?;
    t += dt;

    // Pair 2: rust-lang.org → A
    let q2 = build_dns_a_query(0x5678, "rust-lang.org");
    let r2 = build_dns_a_response(0x5678, "rust-lang.org", [54, 230, 66, 65]);
    write(
        &mut pw,
        t,
        &ipv4_udp(client_ip, resolver_ip, cport, sport, &q2),
    )?;
    t += dt;
    write(
        &mut pw,
        t,
        &ipv4_udp(resolver_ip, client_ip, sport, cport, &r2),
    )?;
    t += dt;

    // Lone NXDOMAIN response (no matching query)
    write(
        &mut pw,
        t,
        &ipv4_udp(resolver_ip, client_ip, sport, cport, &r_nxdomain),
    )?;
    t += dt;

    // Lone unanswered query (no response will follow)
    write(
        &mut pw,
        t,
        &ipv4_udp(client_ip, resolver_ip, cport, sport, &q_a_other),
    )?;

    Ok(())
}

/// Mixed protocols: TCP + UDP + ICMP echo.
fn write_mixed_short(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut pw = pcap_writer(BufWriter::new(File::create(path)?))?;

    let h1 = [10, 1, 1, 1];
    let h2 = [10, 1, 1, 2];

    let mut t = Duration::from_micros(0);
    let dt = Duration::from_micros(200);

    // Two short TCP exchanges
    let mac_a = [0x02, 0, 0, 0, 1, 1];
    let mac_b = [0x02, 0, 0, 0, 1, 2];
    write(
        &mut pw,
        t,
        &ipv4_tcp(mac_a, mac_b, h1, h2, 33_000, 22, 100, 0, 0x02, b""),
    )?;
    t += dt;
    write(
        &mut pw,
        t,
        &ipv4_tcp(mac_b, mac_a, h2, h1, 22, 33_000, 200, 101, 0x12, b""),
    )?;
    t += dt;
    write(
        &mut pw,
        t,
        &ipv4_tcp(mac_a, mac_b, h1, h2, 33_000, 22, 101, 201, 0x10, b""),
    )?;
    t += dt;

    // UDP one-way
    write(
        &mut pw,
        t,
        &ipv4_udp(h1, h2, 12_345, 514, b"<14>test syslog"),
    )?;
    t += dt;

    // ICMP echo via etherparse-built frame
    write(&mut pw, t, &build_icmp_echo(h1, h2, 1, 1))?;
    t += dt;
    write(&mut pw, t, &build_icmp_echo(h2, h1, 1, 1))?;
    t += dt;

    // Another UDP DNS-shaped packet
    let q = build_dns_a_query(0xdead, "mixed.test");
    write(&mut pw, t, &ipv4_udp(h1, h2, 53_001, 53, &q))?;

    Ok(())
}

// ── tiny DNS message builders (RFC 1035 wire format) ────────────────

fn build_dns_a_query(tx_id: u16, qname: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tx_id.to_be_bytes());
    v.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD
    v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    v.extend_from_slice(&0u16.to_be_bytes()); // ancount
    v.extend_from_slice(&0u16.to_be_bytes()); // nscount
    v.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    v.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    v
}

fn build_dns_a_response(tx_id: u16, qname: &str, addr: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tx_id.to_be_bytes());
    v.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: response, RA
    v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    v.extend_from_slice(&1u16.to_be_bytes()); // ancount
    v.extend_from_slice(&0u16.to_be_bytes()); // nscount
    v.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    v.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

    // Answer
    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes()); // type A
    v.extend_from_slice(&1u16.to_be_bytes()); // class IN
    v.extend_from_slice(&60u32.to_be_bytes()); // TTL
    v.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    v.extend_from_slice(&addr);
    v
}

fn build_dns_nxdomain(tx_id: u16, qname: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tx_id.to_be_bytes());
    v.extend_from_slice(&0x8183u16.to_be_bytes()); // flags: response, NXDOMAIN
    v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    v.extend_from_slice(&0u16.to_be_bytes()); // ancount
    v.extend_from_slice(&0u16.to_be_bytes()); // nscount
    v.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    v.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    v
}

fn encode_qname(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

// ── ICMP echo ────────────────────────────────────────────────────

fn build_icmp_echo(src: [u8; 4], dst: [u8; 4], ident: u16, seq: u16) -> Vec<u8> {
    use etherparse::{EtherType, Ethernet2Header, IpNumber, Ipv4Header};

    // ICMP Echo Request: type=8, code=0, checksum, identifier, seq, payload
    let payload = [0u8; 8];
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // type Echo Request
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(&payload);
    let csum = ones_complement_sum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let ip = Ipv4Header::new(icmp.len() as u16, 64, IpNumber::ICMP, src, dst).unwrap();
    let eth = Ethernet2Header {
        destination: [0; 6],
        source: [0; 6],
        ether_type: EtherType::IPV4,
    };

    let mut out = Vec::new();
    eth.write(&mut out).unwrap();
    ip.write(&mut out).unwrap();
    out.extend_from_slice(&icmp);
    out
}

fn ones_complement_sum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
