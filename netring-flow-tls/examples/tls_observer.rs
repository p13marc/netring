//! Print SNI / ALPN / cipher list for every TLS ClientHello in a
//! pcap. Demonstrates the netring-flow-pcap + netring-flow +
//! netring-flow-tls pipeline.
//!
//! Usage:
//!     cargo run -p netring-flow-tls --example tls_observer -- trace.pcap

use std::env;

use netring_flow::extract::FiveTuple;
use netring_flow::{FlowDriver, FlowEvent};
use netring_flow_pcap::PcapFlowSource;
use netring_flow_tls::{TlsClientHello, TlsFactory, TlsHandler, TlsServerHello};

struct Logger;

impl TlsHandler for Logger {
    fn on_client_hello(&self, h: &TlsClientHello) {
        let sni = h.sni.as_deref().unwrap_or("(no SNI)");
        let alpn = if h.alpn.is_empty() {
            "(no ALPN)".to_string()
        } else {
            h.alpn.join(",")
        };
        println!(
            "→ ClientHello sni={sni:?} alpn={alpn} ciphers={n} ext_count={ec}",
            n = h.cipher_suites.len(),
            ec = h.extension_types.len()
        );
    }
    fn on_server_hello(&self, h: &TlsServerHello) {
        println!(
            "← ServerHello cipher=0x{c:04x} alpn={alpn:?}",
            c = h.cipher_suite,
            alpn = h.alpn
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: tls_observer <trace.pcap>")?;

    let factory = TlsFactory::with_handler(Logger);
    let mut driver: FlowDriver<FiveTuple, _, ()> =
        FlowDriver::new(FiveTuple::bidirectional(), factory);

    let mut started = 0u64;
    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        for ev in driver.track(view.as_view()) {
            if matches!(ev, FlowEvent::Started { .. }) {
                started += 1;
            }
        }
    }
    eprintln!("\n--- summary: {started} flows seen");
    Ok(())
}
