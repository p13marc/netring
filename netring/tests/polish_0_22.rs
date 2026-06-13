//! 0.22 §7 polish: `MinSeverity::info()` (const family) + `tick_ctx`
//! (Tick payload elision via the `CtxOnly` marker).

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::time::Duration;

use netring::layer::MinSeverity;
use netring::monitor::Monitor;
use netring::prelude::*;

// `MinSeverity` constructors are `const` (usable in const context).
const _INFO: MinSeverity = MinSeverity::info();
const _WARN: MinSeverity = MinSeverity::warning();

#[test]
fn tick_ctx_elides_the_payload_and_builds() {
    // `|ctx|` — no `&Tick` to destructure. Would be ambiguous through
    // `.tick` (PayloadOnly vs CtxOnly are both arity-1); `tick_ctx`
    // fixes the marker.
    let _m: Monitor = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .tick_ctx(Duration::from_secs(1), |ctx: &mut Ctx<'_>| {
            let _ = ctx.ts;
            Ok(())
        })
        .layer(MinSeverity::info())
        .sink(StdoutSink::default())
        .build()
        .expect("builds");
}
