//! Live VLAN tests on a veth pair with an 802.1Q sub-interface.
//!
//! `A.100` (VLAN 100 on veth end `A`) transmits; the tag travels as skb
//! metadata (veth has VLAN TX offload) and the receiving end `B` hands it to
//! packet taps that way too — Linux strips / keeps the outer tag out of the
//! frame before the socket filter runs. So a `vlan` filter must read the tag
//! from the metadata (#208).
//!
//! Needs `CAP_NET_ADMIN` (veth + vlan) and `CAP_NET_RAW`; skips without
//! them or without the `8021q` module.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::process::Command;
use std::time::{Duration, Instant};

use helpers::VethPair;
use netring::{BpfFilter, Capture, CaptureBuilder, Error, Injector};

const MARKER: &[u8; 8] = b"NRVLANTS";
/// Ethernet + IPv4 + UDP headers in front of the payload (untagged frame).
const PAYLOAD_OFF: usize = 14 + 20 + 8;

/// A veth pair `A` / `B` plus `A.100`, removed on drop.
struct VlanLink {
    veth: VethPair,
    vlan: String,
}

impl VlanLink {
    /// `None` (skip) without privileges or the 8021q module.
    fn create(tag: &str, vid: u16) -> Option<Self> {
        let pid = std::process::id() % 100_000;
        let veth = match VethPair::create(&format!("s2v{tag}{pid}a"), &format!("s2v{tag}{pid}b")) {
            Some(v) => v,
            None => {
                eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
                return None;
            }
        };
        let vlan = format!("{}.{vid}", veth.a);
        let ok = Command::new("ip")
            .args([
                "link", "add", "link", &veth.a, "name", &vlan, "type", "vlan",
            ])
            .args(["id", &vid.to_string()])
            .status()
            .is_ok_and(|s| s.success())
            && Command::new("ip")
                .args(["link", "set", &vlan, "up"])
                .status()
                .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("skipping: cannot create a VLAN device (8021q module?)");
            return None;
        }
        Some(Self { veth, vlan })
    }
}

impl Drop for VlanLink {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", &self.vlan])
            .output();
    }
}

fn open(builder: CaptureBuilder) -> Option<Capture> {
    match builder.build() {
        Ok(cap) => Some(cap),
        Err(Error::PermissionDenied) => {
            eprintln!("skipping: needs CAP_NET_RAW");
            None
        }
        Err(e) => panic!("build capture: {e}"),
    }
}

/// An untagged broadcast IPv4/UDP frame to `port` carrying `MARKER` + `seq`.
fn udp_frame(port: u16, seq: u32) -> Vec<u8> {
    let mut payload = MARKER.to_vec();
    payload.extend_from_slice(&seq.to_be_bytes());
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0x5a, 0x01]);
    f.extend_from_slice(&[0x08, 0x00]);
    let ip_len = (20 + 8 + payload.len()) as u16;
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&ip_len.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    f.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    f.extend_from_slice(&40_000u16.to_be_bytes());
    f.extend_from_slice(&port.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&payload);
    f
}

/// Send `n` frames out of `iface` (`A.100` adds the tag).
fn inject(iface: &str, port: u16, n: u32) {
    let mut tx = Injector::builder()
        .interface(iface)
        .frame_count(n.max(1) as usize)
        .build()
        .expect("injector");
    for seq in 0..n {
        let frame = udp_frame(port, seq);
        let mut slot = tx.allocate(frame.len()).expect("allocate");
        slot.data_mut()[..frame.len()].copy_from_slice(&frame);
        slot.set_len(frame.len());
        slot.send();
    }
    tx.flush().expect("flush");
    tx.wait_drained(Duration::from_secs(2)).expect("drained");
}

/// Whether `data` carries our marker (after the untagged headers, or after
/// one in-frame tag).
fn is_ours(data: &[u8]) -> bool {
    [PAYLOAD_OFF, PAYLOAD_OFF + 4]
        .iter()
        .any(|&o| data.get(o..o + MARKER.len()) == Some(&MARKER[..]))
}

/// Count our frames on `cap` for `window`.
fn count_ours(cap: &mut Capture, window: Duration) -> usize {
    let mut n = 0;
    let deadline = Instant::now() + window;
    let mut pkts = cap.packets_until(deadline);
    while let Some(pkt) = pkts.next_packet() {
        if is_ours(pkt.data()) {
            n += 1;
        }
    }
    n
}

fn vlan_filter(vid: u16, port: u16) -> BpfFilter {
    BpfFilter::builder()
        .vlan()
        .vlan_id(vid)
        .udp()
        .dst_port(port)
        .build()
        .expect("filter")
}

/// #208: the receiving end gets the tag as metadata; `vlan().vlan_id(100)`
/// must match it and `vlan_id(101)` must not. On 0.31 the filter only
/// looked for an in-frame tag, so neither matched.
#[test]
fn vlan_filter_matches_the_kernel_stripped_tag() {
    let Some(link) = VlanLink::create("f", 100) else {
        return;
    };
    let port = 41_000 + (std::process::id() % 1_000) as u16;
    let base = || {
        Capture::builder()
            .interface(&link.veth.b)
            .block_timeout_ms(10)
            .poll_timeout(Duration::from_millis(50))
    };
    let Some(mut hit) = open(base().bpf_filter(vlan_filter(100, port))) else {
        return;
    };
    let Some(mut miss) = open(base().bpf_filter(vlan_filter(101, port))) else {
        return;
    };

    inject(&link.vlan, port, 5);
    assert_eq!(
        count_ours(&mut hit, Duration::from_secs(1)),
        5,
        "vlan 100 sees the frames"
    );
    assert_eq!(
        count_ours(&mut miss, Duration::from_millis(300)),
        0,
        "vlan 101 does not"
    );
}
