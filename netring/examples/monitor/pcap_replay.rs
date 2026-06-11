//! 0.21 E.1/E.3: `Monitor::replay` over an offline pcap file.
//!
//! Loads the pcap, drives the monitor's dispatcher to EOF, then
//! runs the graceful drain phase before returning.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_pcap_replay \
//!     --features "tokio,flow,pcap" -- path/to/capture.pcap
//! ```

use netring::prelude::*;
use netring::protocol::event_typed::{FlowEnded, FlowStarted};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pcap = std::env::args()
        .nth(1)
        .ok_or("usage: monitor_pcap_replay <path.pcap>")?;

    Monitor::builder()
        .pcap_source(&pcap)
        .protocol::<Tcp>()
        .protocol::<Udp>()
        .name("pcap-replay-demo")
        .on::<FlowStarted<Tcp>>(|e: &FlowStarted<Tcp>| {
            println!("[tcp] started key={:?}", e.key);
            Ok(())
        })
        .on::<FlowStarted<Udp>>(|e: &FlowStarted<Udp>| {
            println!("[udp] started key={:?}", e.key);
            Ok(())
        })
        .on::<FlowEnded<Tcp>>(|e: &FlowEnded<Tcp>| {
            println!(
                "[tcp] ended   key={:?} reason={:?} pkts_a={} pkts_b={}",
                e.key, e.reason, e.stats.packets_initiator, e.stats.packets_responder
            );
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .replay()
        .await?;

    Ok(())
}
