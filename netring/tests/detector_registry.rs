//! Detector registry wiring (issue #127).
//!
//! Cap-free: `.detector(..)` / `.detectors(..)` accept flowscope detectors, seed
//! a `DetectorCell` at build, and the Monitor builds without a capture. The
//! detectors' emission logic is unit-tested upstream in flowscope; the ATT&CK
//! observation append is tested in `netring::anomaly::sink`.

#![cfg(all(feature = "tokio", feature = "flow"))]

use flowscope::detect::patterns::{BeaconDetector, PortScanDetector};
use flowscope::detect::{DetectorRegistry, HostPair, SrcHost};
use flowscope::extract::FiveTupleKey;
use netring::monitor::Monitor;
use netring::prelude::StdoutSink;

#[tokio::test(flavor = "current_thread")]
async fn detector_builds_and_accumulates() {
    let m = Monitor::builder()
        .interface("lo")
        .detector(PortScanDetector::<SrcHost>::new())
        .detector(BeaconDetector::<HostPair>::new())
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "detector build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
async fn detectors_registry_builds() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(PortScanDetector::<SrcHost>::new());
    let m = Monitor::builder()
        .interface("lo")
        .detectors(reg)
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "detectors registry build failed: {:?}", m.err());
}
