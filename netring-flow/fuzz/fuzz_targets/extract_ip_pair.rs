#![no_main]

use libfuzzer_sys::fuzz_target;
use netring_flow::extract::IpPair;
use netring_flow::{FlowExtractor, PacketView, Timestamp};

fuzz_target!(|data: &[u8]| {
    let view = PacketView::new(data, Timestamp::default());
    let _ = IpPair.extract(view);
});
