//! `MonitorBuilder` network-namespace capture (issue #135).
//!
//! Two halves, deliberately split by privilege:
//!
//! * the wiring — plan description, `capture_sources()` ordering, the AF_XDP
//!   rejection — is asserted against the *current* namespace, which every
//!   process can open, so it runs unprivileged in the normal CI lane;
//! * actually entering a namespace needs `CAP_SYS_ADMIN`, so anything that
//!   reaches `setns(2)` skips on `EPERM` rather than failing. See
//!   `netns_capture.rs` for why the guard is the outcome and not `geteuid()`.

#![cfg(all(feature = "tokio", feature = "flow", feature = "monitor"))]

use std::sync::Arc;

use netring::monitor::{Backend, CaptureSourceBackend, Monitor};
use netring::netns::NetNs;

/// Can this process actually `setns` into its own namespace?
fn can_enter_netns(ns: &NetNs) -> bool {
    match ns.run_in(|| ()) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(e) => panic!("setns failed for a reason other than privilege: {e}"),
    }
}

#[test]
fn capture_sources_is_indexed_by_source_idx() {
    // The whole point of the accessor: position == the SourceIdx handlers see.
    let built = Monitor::builder()
        .interfaces(["lo", "lo"])
        .build()
        .expect("two host interfaces build");

    let sources = built.capture_sources();
    assert_eq!(sources.len(), 2);
    for (i, s) in sources.iter().enumerate() {
        assert_eq!(s.interface, "lo", "source {i}");
        assert_eq!(s.backend, CaptureSourceBackend::AfPacket);
        assert_eq!(s.netns_label, None, "no namespace was requested");
    }
}

#[test]
fn explicit_af_xdp_in_a_netns_is_rejected_at_build() {
    // Only meaningful when an AF_XDP backend can be named at all.
    #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
    {
        let ns = Arc::new(NetNs::current().expect("open /proc/self/ns/net"));
        let err = Monitor::builder()
            .capture_in_netns("lo", Backend::af_xdp(), ns)
            .build()
            .expect_err("AF_XDP in a namespace must not build");
        let msg = err.to_string();
        assert!(
            msg.contains("AF_XDP") && msg.contains("lo"),
            "error should name the backend and the interface, got: {msg}"
        );
    }
}

#[test]
fn auto_resolves_to_af_packet_for_a_namespaced_source() {
    // `Auto` would prefer self-loading AF_XDP wherever `xdp-loader` is compiled
    // in. With a namespace it must come down on AF_PACKET instead — and unlike
    // an *explicit* AF_XDP request, that is a resolution, not an error.
    let ns = Arc::new(NetNs::current().expect("open /proc/self/ns/net"));
    if !can_enter_netns(&ns) {
        eprintln!("skipping: setns needs CAP_SYS_ADMIN");
        return;
    }
    let built = Monitor::builder()
        .capture_in_netns("lo", Backend::Auto, ns)
        .build()
        .expect("Auto + netns builds as AF_PACKET");

    let sources = built.capture_sources();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].backend, CaptureSourceBackend::AfPacket);
    assert_eq!(sources[0].netns_label.as_deref(), Some("current"));
}

#[test]
fn host_and_namespaced_sources_compose_and_stay_distinguishable() {
    let ns = Arc::new(NetNs::current().expect("open /proc/self/ns/net"));
    if !can_enter_netns(&ns) {
        eprintln!("skipping: setns needs CAP_SYS_ADMIN");
        return;
    }
    let built = Monitor::builder()
        .capture("lo", Backend::af_packet())
        .capture_in_netns("lo", Backend::af_packet(), Arc::clone(&ns))
        .build()
        .expect("host + namespaced sources build");

    let sources = built.capture_sources();
    assert_eq!(sources.len(), 2, "one source per capture() call");
    // Same interface name in both — the namespace is the only thing telling
    // them apart, which is exactly the case the accessor exists for.
    assert_eq!(sources[0].interface, "lo");
    assert_eq!(sources[0].netns_label, None, "host source");
    assert_eq!(sources[1].interface, "lo");
    assert_eq!(
        sources[1].netns_label.as_deref(),
        Some("current"),
        "namespaced source"
    );
}

#[test]
fn the_resolved_plan_records_the_namespace() {
    let ns = Arc::new(NetNs::current().expect("open /proc/self/ns/net"));
    if !can_enter_netns(&ns) {
        eprintln!("skipping: setns needs CAP_SYS_ADMIN");
        return;
    }
    let builder = Monitor::builder().capture_in_netns("lo", Backend::af_packet(), ns);
    let plan = builder.resolved_capture_plan();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].0, "lo");
    assert!(
        plan[0].1.contains("netns current"),
        "plan should name the namespace so an operator can see it without logs, got: {}",
        plan[0].1
    );
}
