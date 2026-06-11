//! 0.21 A.6: build-time validation that detectors declaring a
//! counter type `K` via `detector! { counters: [K], … }` actually
//! see a `.counter::<K>(window, bucket)` registration on the
//! builder. Negative test: misspelt / forgotten `.counter::<K>()`
//! turns into `BuildError::CounterNotRegistered` before the
//! first packet arrives. Positive test: matching declaration +
//! registration builds successfully.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::IpAddr;
use std::time::Duration;

use netring::detector;
use netring::error::{BuildError, Error};
use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

#[test]
fn build_fails_when_declared_counter_is_not_registered() {
    let det = detector! {
        name: "MissingCounter",
        counters: [IpAddr],
        severity: Warning,
        event: FlowStarted<Tcp>,
        emit: |_evt, ctx| {
            let now = ctx.ts;
            ctx.counter_mut::<IpAddr>().bump(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                now,
            );
        },
    };

    // Deliberately omit `.counter::<IpAddr>(...)` — build must reject.
    let err = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .detect(det)
        .build()
        .expect_err("build() should reject detector with undeclared counter");

    match err {
        Error::Build(BuildError::CounterNotRegistered {
            detector,
            type_name,
        }) => {
            assert_eq!(detector, "MissingCounter");
            assert!(
                type_name.ends_with("IpAddr"),
                "expected type_name to end with IpAddr, got `{type_name}`"
            );
        }
        other => panic!("expected CounterNotRegistered, got {other:?}"),
    }
}

#[test]
fn build_succeeds_when_declared_counter_is_registered() {
    let det = detector! {
        name: "HasCounter",
        counters: [IpAddr],
        severity: Info,
        event: FlowStarted<Tcp>,
        emit: |_evt, ctx| {
            let now = ctx.ts;
            ctx.counter_mut::<IpAddr>().bump(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                now,
            );
        },
    };

    let _monitor = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .counter::<IpAddr>(Duration::from_secs(60), Duration::from_secs(1))
        .detect(det)
        .build()
        .expect("build with declared+registered counter should succeed");
}

#[test]
fn build_skips_validation_when_no_counters_clause() {
    // No `counters:` clause → `declared_counters` defaults to `&[]`
    // → validation walk is a no-op. Detector compiles and builds
    // even without any registered counters.
    let det = detector! {
        name: "NoCounters",
        severity: Info,
        event: FlowStarted<Tcp>,
        emit: |_evt, _ctx| {
            // Body intentionally empty.
        },
    };

    let _monitor = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .detect(det)
        .build()
        .expect("build with empty declared_counters skips validation");
}
