//! Rotating + triggered pcap capture (issue #125): a DFIR "capture the lead-up
//! to an event" recorder.
//!
//! [`RotatingPcapWriter`] owns its files and rolls over on size/duration with a
//! retention bound. [`TriggeredPcapWriter`] wraps it with a bytes-bounded
//! pre-trigger ring: packets are buffered until a [`TriggerHandle`] fires (from
//! any anomaly handler / control task), at which point the ring is flushed and
//! subsequent packets stream to disk — so the capture includes what happened
//! *before* you noticed.
//!
//! This standalone demo feeds synthetic frames to show the buffer-then-flush
//! behaviour (wiring it to a live tap via `with_pcap_tap` is a follow-up).
//!
//! ```sh
//! cargo run --example monitor_triggered_pcap --features "pcap" -- /tmp/dfir
//! ```

use netring::packet::Timestamp;
use netring::pcap_rotate::{RotatingConfig, RotatingPcapWriter, TriggeredPcapWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());

    // 128 MiB files, keep 16 — the "capture forever without filling the disk"
    // default; here we just demonstrate the trigger.
    let rotating = RotatingPcapWriter::create(&dir, "incident", RotatingConfig::default())?;
    // 1 MiB pre-trigger ring.
    let (mut writer, trigger) = TriggeredPcapWriter::new(1 << 20, rotating);

    // A minimal Ethernet+IPv4 frame stand-in (content is irrelevant here).
    let frame = [0u8; 64];

    // Pre-trigger: these land in the ring, nothing on disk yet.
    for i in 0..10 {
        writer.write_raw(&frame, Timestamp::new(100 + i, 0), frame.len())?;
    }
    println!("buffered 10 frames (recording: {})", writer.is_recording());

    // An anomaly handler would call `trigger.fire()`. After firing, the ring is
    // flushed and subsequent frames stream live.
    trigger.fire();
    for i in 0..10 {
        writer.write_raw(&frame, Timestamp::new(200 + i, 0), frame.len())?;
    }
    writer.sync_and_close()?;
    println!("fired → flushed ring + recorded live into {dir}/incident-*.pcap");
    Ok(())
}
