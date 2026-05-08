//! Multi-threaded fanout capture example.
//!
//! Usage: cargo run --example fanout -- [interface] [num_threads]

use netring::{Capture, FanoutFlags, FanoutMode};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let num_threads: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    eprintln!("Fanout capture on {iface} with {num_threads} threads...");

    let counters: Vec<Arc<AtomicU64>> = (0..num_threads)
        .map(|_| Arc::new(AtomicU64::new(0)))
        .collect();

    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let iface = iface.clone();
            let counter = Arc::clone(&counters[i]);

            thread::spawn(move || {
                // Pin thread to CPU for NUMA-aware capture
                if let Some(core_ids) = core_affinity::get_core_ids() {
                    if let Some(core) = core_ids.get(i % core_ids.len()) {
                        core_affinity::set_for_current(*core);
                    }
                }

                let mut cap = Capture::builder()
                    .interface(&iface)
                    .fanout(FanoutMode::Cpu, 42)
                    .fanout_flags(FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG)
                    .ignore_outgoing(true)
                    .build()
                    .expect("build capture");

                for pkt in cap.packets().take(100) {
                    let _ = pkt.data();
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    for (i, c) in counters.iter().enumerate() {
        eprintln!("Thread {i}: {} packets", c.load(Ordering::Relaxed));
    }
    Ok(())
}
