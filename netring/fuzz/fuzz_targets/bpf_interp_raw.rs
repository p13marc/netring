#![no_main]
//! Fuzz the cBPF software interpreter (`BpfFilter::matches`) against **raw,
//! arbitrary bytecode** — not the validated output of the typed builder.
//!
//! The existing `bpf_matches` / `bpf_builder` targets only ever feed the
//! interpreter programs produced by the *validating* `BpfFilterBuilder`, so
//! the interpreter is never exercised against hostile opcodes (unknown
//! `code`s, out-of-range jump offsets, OOB `k`). `BpfFilter::new` only checks
//! the instruction count, and `BpfInsn` has fully public fields — so this
//! target hands the interpreter adversarial programs directly.
//!
//! The interpreter must, for any program and any frame: never panic, never
//! read out of bounds, and always terminate (classic BPF jumps are
//! forward-only, so a correct interpreter that bounds the program counter
//! cannot loop forever).
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use netring::config::{BpfFilter, BpfInsn};

#[derive(Arbitrary, Debug)]
struct Input {
    /// Raw `(code, jt, jf, k)` instruction tuples — arbitrary bytecode.
    insns: Vec<(u16, u8, u8, u32)>,
    /// The untrusted frame the program runs over.
    frame: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Cap at the kernel's program-size limit so `new` accepts it and we
    // exercise the interpreter rather than the length guard.
    let insns: Vec<BpfInsn> = input
        .insns
        .into_iter()
        .take(BpfFilter::MAX_INSNS)
        .map(|(code, jt, jf, k)| BpfInsn { code, jt, jf, k })
        .collect();

    let Ok(filter) = BpfFilter::new(insns) else {
        return;
    };

    // Must not panic / OOB / hang on adversarial bytecode + frame.
    let a = filter.matches(&input.frame);
    // Matching is a pure function of (program, frame).
    let b = filter.matches(&input.frame);
    assert_eq!(a, b);
});
