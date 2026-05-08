//! Build a custom flow extractor and run it against packets
//! captured live via `AsyncCapture`.
//!
//! Plan 01 demonstrates the extractor surface: given a `Packet`,
//! call `pkt.view()` to get a `PacketView`, then pass that to a
//! `FlowExtractor`. Plan 02 will replace this loop with
//! `cap.flow_stream(extractor)`.
//!
//! Usage:
//!     cargo run -p netring --example async_flow_keys --features tokio,parse -- eth0

use std::env;

use netring::AsyncCapture;
use netring::flow::extract::{FiveTuple, StripVlan};
use netring::flow::{Extracted, FlowExtractor, L4Proto, Orientation, PacketView};

/// Custom extractor: keys flows by (proto, lower-port) — useful
/// when you want to aggregate traffic per service regardless of
/// client identity. Demonstrates how easy it is to roll your own.
#[derive(Debug, Default)]
struct ServicePort;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct ServiceKey {
    proto: L4Proto,
    port: u16,
}

impl FlowExtractor for ServicePort {
    type Key = ServiceKey;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<ServiceKey>> {
        let parsed = etherparse::SlicedPacket::from_ethernet(view.frame).ok()?;
        let _ = parsed.net?;
        let (src_port, dst_port, proto) = match parsed.transport? {
            etherparse::TransportSlice::Tcp(t) => {
                (t.source_port(), t.destination_port(), L4Proto::Tcp)
            }
            etherparse::TransportSlice::Udp(u) => {
                (u.source_port(), u.destination_port(), L4Proto::Udp)
            }
            _ => return None,
        };
        // The "service" is the lower port — stable regardless of
        // which side initiated.
        let port = src_port.min(dst_port);
        let orientation = if port == dst_port {
            Orientation::Forward
        } else {
            Orientation::Reverse
        };
        Some(Extracted {
            key: ServiceKey { proto, port },
            orientation,
            l4: Some(proto),
            tcp: None,
        })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    println!("listening on {iface} — capturing up to 20 packets...");

    let mut cap = AsyncCapture::open(&iface)?;
    let extractor_a = StripVlan(FiveTuple::bidirectional());
    let extractor_b = ServicePort;

    let mut shown = 0usize;
    'outer: while shown < 20 {
        let batch = cap.recv().await?;
        for pkt in &batch {
            if shown >= 20 {
                break 'outer;
            }
            let view = PacketView::new(&pkt.data, pkt.timestamp);
            match extractor_a.extract(view) {
                Some(e) => println!(
                    "[{shown:02}] 5tuple: {proto:?} {a} <-> {b}",
                    proto = e.key.proto,
                    a = e.key.a,
                    b = e.key.b,
                ),
                None => println!("[{shown:02}] (5tuple: not parseable)"),
            }
            if let Some(e) = extractor_b.extract(view) {
                println!("       service: {:?} :{}", e.key.proto, e.key.port);
            }
            shown += 1;
        }
    }
    Ok(())
}
