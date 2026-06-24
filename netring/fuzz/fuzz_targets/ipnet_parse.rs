#![no_main]
//! Fuzz the zero-dep `IpNet` (`addr/prefix`) parser against arbitrary,
//! untrusted strings. `IpNet` parses operator-supplied CIDRs from config / CLI
//! / control-plane input (IOC subnets, allow/deny nets), so it's a classic
//! untrusted-input surface: it must never panic, read OOB, or loop forever.
//!
//! On a successful parse we additionally assert two invariants the rest of the
//! code relies on:
//!   1. **Round-trip:** `Display` then re-parse yields an *equal* `IpNet`. The
//!      parser must not silently drop or mutate the value it accepted.
//!   2. **`contains` is total:** the masking math must not panic for any prefix
//!      (incl. the `/0` and `/128` boundaries) against either address family.
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netring::config::IpNet;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Parsing must never panic. A parse error is a normal, expected outcome.
    let Ok(net) = s.parse::<IpNet>() else {
        return;
    };

    // 1. Display → re-parse must round-trip to an equal value.
    let rendered = net.to_string();
    let reparsed: IpNet = rendered
        .parse()
        .expect("a rendered IpNet must always re-parse");
    assert_eq!(
        net, reparsed,
        "round-trip changed the value: {s:?} -> {rendered:?}"
    );

    // 2. `contains` must be total over both families and every prefix.
    let probes = [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    for ip in probes {
        let _ = net.contains(&ip);
    }
});
