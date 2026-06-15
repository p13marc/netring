#![no_main]
//! Fuzz the hand-rolled `.expr()` filter-string parser (0.25 A4) against
//! arbitrary, untrusted strings. The parser is the classic untrusted-input
//! attack surface (config / CLI / control-plane filters); it must never panic,
//! read OOB, or loop forever on adversarial input. On a successful parse the
//! resulting `Predicate` is run through `kernel_approx` + `eval` to prove the
//! downstream AST consumers are robust too.
use libfuzzer_sys::fuzz_target;
use netring::monitor::subscription::{FieldSource, parse_expr};

/// An all-`None` field source — exercises the "absent field ⇒ false" paths.
struct Nothing;
impl FieldSource for Nothing {}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Parsing must never panic. A parse error is a normal outcome.
    if let Ok(pred) = parse_expr(s) {
        // Determinism + no-panic through the consumers an `.expr()` predicate
        // flows into: userspace eval, the kernel-approx split, and the
        // fully-pushable classifier.
        let a = pred.eval(&Nothing);
        let b = pred.eval(&Nothing);
        assert_eq!(a, b, "eval must be a pure function of (predicate, source)");
        let k = pred.kernel_approx();
        let _ = k.eval(&Nothing);
        let _ = pred.is_fully_kernel_pushable();
    }
});
