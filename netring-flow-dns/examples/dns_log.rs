//! Print a one-line summary for every DNS query/response observed
//! in a pcap. Demonstrates the netring-flow-pcap + netring-flow +
//! netring-flow-dns pipeline using the [`DnsUdpObserver`] tap.
//!
//! Usage:
//!     cargo run -p netring-flow-dns --example dns_log -- trace.pcap

use std::env;

use netring_flow::extract::FiveTuple;
use netring_flow::{FlowTracker, Timestamp};
use netring_flow_dns::{DnsHandler, DnsQuery, DnsRdata, DnsResponse, DnsUdpObserver};
use netring_flow_pcap::PcapFlowSource;

struct Logger;

impl DnsHandler for Logger {
    fn on_query(&self, q: &DnsQuery) {
        let names: Vec<&str> = q.questions.iter().map(|q| q.name.as_str()).collect();
        println!("→ Q  id=0x{:04x} {}", q.transaction_id, names.join(","));
    }
    fn on_response(&self, r: &DnsResponse) {
        let n = r.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
        let ms = r
            .elapsed
            .map(|d| format!(" rtt={:.2}ms", d.as_secs_f64() * 1000.0))
            .unwrap_or_default();
        let preview = r
            .answers
            .iter()
            .take(2)
            .map(|a| match &a.data {
                DnsRdata::A(ip) => ip.to_string(),
                DnsRdata::AAAA(ip) => ip.to_string(),
                DnsRdata::CNAME(s) | DnsRdata::NS(s) | DnsRdata::PTR(s) => s.clone(),
                DnsRdata::MX { exchange, .. } => exchange.clone(),
                _ => "<…>".to_string(),
            })
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "← R  id=0x{:04x} {} rcode={:?} answers={}{}{}",
            r.transaction_id,
            n,
            r.rcode,
            r.answers.len(),
            if preview.is_empty() {
                String::new()
            } else {
                format!(" [{preview}]")
            },
            ms
        );
    }
    fn on_unanswered(&self, q: &DnsQuery) {
        let n = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
        println!("⏱  unanswered id=0x{:04x} {n}", q.transaction_id);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: dns_log <trace.pcap>")?;

    // DnsUdpObserver wraps an inner FlowExtractor and fires DNS events
    // as a side effect of extraction. We don't need TCP reassembly for
    // UDP/53, so plug it straight into a FlowTracker (no FlowDriver).
    let observer = DnsUdpObserver::new(FiveTuple::bidirectional(), Logger);
    let mut tracker: FlowTracker<_, ()> = FlowTracker::new(observer);

    let mut last_sweep_sec: u32 = 0;
    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        let now = view.timestamp;
        for _ev in tracker.track(view.as_view()) {}
        // Sweep unanswered queries roughly once per second of trace time.
        let now_sec = now.to_duration().as_secs() as u32;
        if now_sec > last_sweep_sec {
            tracker.extractor().sweep_unanswered(now);
            last_sweep_sec = now_sec;
        }
    }
    // Final sweep — flush anything still pending at end of trace.
    tracker
        .extractor()
        .sweep_unanswered(Timestamp::new(u32::MAX, 0));
    Ok(())
}
