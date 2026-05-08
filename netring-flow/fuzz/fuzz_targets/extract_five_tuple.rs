#![no_main]

use libfuzzer_sys::fuzz_target;
use netring_flow::extract::FiveTuple;
use netring_flow::{FlowExtractor, PacketView, Timestamp};

fuzz_target!(|data: &[u8]| {
    let view = PacketView::new(data, Timestamp::default());
    // Should never panic, regardless of input shape.
    let _ = FiveTuple::bidirectional().extract(view);
    let _ = FiveTuple::directional().extract(view);
});
