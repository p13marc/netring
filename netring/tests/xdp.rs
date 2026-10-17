//! AF_XDP integration smoke test.
//!
//! Most XDP-bind paths require kernel features (a NIC with XDP-capable
//! driver) that aren't available in every CI environment. The test below
//! attempts to open a Tx-only socket on `lo` and skips gracefully if the
//! kernel rejects the bind (typical for the GitHub-hosted runner without
//! XDP support on lo, where bind returns EOPNOTSUPP / ENODEV).

#![cfg(all(feature = "integration-tests", feature = "af-xdp"))]

use netring::{XdpMode, XdpSocketBuilder};

#[test]
fn xdp_open_tx_only_or_skip() {
    let result = XdpSocketBuilder::default()
        .interface("lo")
        .queue_id(0)
        .frame_size(2048)
        .frame_count(64)
        .mode(XdpMode::Tx)
        .build();

    match result {
        Ok(mut xdp) => {
            // Sanity: construct succeeded, we can call statistics()
            // without blowing up.
            let _ = xdp.statistics().expect("statistics");

            // Try sending one tiny frame. send() may report Ok(false)
            // if the TX ring is somehow saturated (shouldn't happen with
            // 64 frames and one send call) — but it must not error.
            let _ = xdp.send(&[0xff; 64]).expect("send");
            let _ = xdp.flush();
        }
        Err(e) => {
            // Common skip cases: no XDP support on lo, no permission.
            eprintln!("skipping AF_XDP smoke test: {e}");
        }
    }
}

/// #213: `RssConfig::set_symmetric` on an interface without configurable
/// RSS (a veth has no `get_rxfh`) is an error and changes nothing. Needs
/// `CAP_NET_ADMIN` for the veth; skips without it.
#[test]
fn symmetric_rss_on_a_veth_is_an_error_and_changes_nothing() {
    use netring::xdp::rss::RssConfig;
    use std::process::Command;

    let pid = std::process::id() % 100_000;
    let (a, b) = (format!("s2r{pid}a"), format!("s2r{pid}b"));
    let created = Command::new("ip")
        .args(["link", "add", &a, "type", "veth", "peer", "name", &b])
        .status()
        .is_ok_and(|s| s.success());
    if !created {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    }
    let rss = RssConfig::new(&a);
    let before = rss.state().map_err(|e| e.to_string());
    let result = rss.set_symmetric();
    let after = rss.state().map_err(|e| e.to_string());
    let _ = Command::new("ip").args(["link", "delete", &a]).output();

    let err = result.expect_err("a veth has no configurable RSS");
    eprintln!("set_symmetric on a veth: {err}");
    assert_eq!(before, after, "the configuration is unchanged");
}
