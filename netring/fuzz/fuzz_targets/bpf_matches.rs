#![no_main]
//! Fuzz the in-tree cBPF software interpreter (`BpfFilter::matches`) against
//! arbitrary, untrusted frame bytes. The interpreter walks L2–L4 offsets into
//! the frame; it must never panic, read out of bounds, or loop forever on a
//! malformed frame. (miri proves the *interpreter's* unsafe-free logic is
//! UB-clean; this proves it's robust against adversarial input.)
use libfuzzer_sys::fuzz_target;
use netring::config::BpfFilter;

fuzz_target!(|frame: &[u8]| {
    // A representative filter exercising ethertype + IP-proto + TCP-port
    // offset walks. The frame is the fuzzed, untrusted input.
    let filter = BpfFilter::builder().tcp().dst_port(443).build().unwrap();
    let a = filter.matches(frame);
    // Determinism: matching is a pure function of (filter, frame).
    let b = filter.matches(frame);
    assert_eq!(a, b);
});
