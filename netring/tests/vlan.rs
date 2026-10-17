//! Live VLAN tests on a veth pair with an 802.1Q sub-interface.
//!
//! `A.100` (VLAN 100 on veth end `A`) transmits; the tag travels as skb
//! metadata (veth has VLAN TX offload) and the receiving end `B` hands it to
//! packet taps that way too — Linux strips / keeps the outer tag out of the
//! frame before the socket filter runs. So a `vlan` filter must read the tag
//! from the metadata (#208), and the ring holds the frame without it unless
//! netring puts it back (#209, libpcap's behaviour, on by default).
//!
//! Needs `CAP_NET_ADMIN` (veth + vlan) and `CAP_NET_RAW`; skips without
//! them or without the `8021q` module.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::process::Command;
use std::time::{Duration, Instant};

use helpers::VethPair;
use netring::{
    BpfFilter, Capture, CaptureBuilder, Error, Injector, OwnedPacket, PacketDirection, VlanProto,
    VlanTag,
};

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
/// one or two in-frame tags).
fn is_ours(data: &[u8]) -> bool {
    [PAYLOAD_OFF, PAYLOAD_OFF + 4, PAYLOAD_OFF + 8]
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

/// The first of our frames on `cap` within 2 s, copied out.
fn first_ours(cap: &mut Capture) -> Option<OwnedPacket> {
    let mut pkts = cap.packets_for(Duration::from_secs(2));
    while let Some(pkt) = pkts.next_packet() {
        if is_ours(pkt.data()) {
            return Some(pkt.to_owned());
        }
    }
    None
}

/// #209: by default the stripped tag is back in the data — the frame as it
/// was on the wire — and both the offline verdict and the kernel's agree.
/// 0.31 handed out the frame without the tag (data[12..14] == 08 00).
#[test]
fn default_capture_reinserts_the_tag() {
    let Some(link) = VlanLink::create("r", 100) else {
        return;
    };
    let port = 42_000 + (std::process::id() % 1_000) as u16;
    let Some(mut cap) = open(
        Capture::builder()
            .interface(&link.veth.b)
            .block_timeout_ms(10)
            .poll_timeout(Duration::from_millis(50)),
    ) else {
        return;
    };
    assert!(cap.vlan_reinsert(), "on by default");
    inject(&link.vlan, port, 1);
    let pkt = first_ours(&mut cap).expect("our frame");

    assert_eq!(&pkt.data[12..18], &[0x81, 0x00, 0x00, 0x64, 0x08, 0x00]);
    let tag = VlanTag::new(100, VlanProto::Dot1Q);
    assert_eq!(pkt.vlan, Some(tag));
    assert!(pkt.status.vlan_reinserted);
    assert_eq!(pkt.stripped_vlan(), None);
    assert_eq!(pkt.data.len(), udp_frame(port, 0).len() + 4);
    assert_eq!(pkt.original_len, pkt.data.len());

    let f = vlan_filter(100, port);
    assert!(f.matches(&pkt.data), "offline: the tag is in the frame");
    assert!(
        f.matches_with(&pkt.data, &pkt.bpf_ancillary()),
        "the kernel's verdict"
    );
    assert!(!vlan_filter(101, port).matches_with(&pkt.data, &pkt.bpf_ancillary()));
}

/// `vlan_reinsert(false)`: the ring as the kernel wrote it, the tag in the
/// metadata only.
#[test]
fn reinsert_off_reports_the_stripped_tag() {
    let Some(link) = VlanLink::create("o", 100) else {
        return;
    };
    let port = 43_000 + (std::process::id() % 1_000) as u16;
    let Some(mut cap) = open(
        Capture::builder()
            .interface(&link.veth.b)
            .vlan_reinsert(false)
            .block_timeout_ms(10)
            .poll_timeout(Duration::from_millis(50)),
    ) else {
        return;
    };
    assert!(!cap.vlan_reinsert());
    inject(&link.vlan, port, 1);
    let pkt = first_ours(&mut cap).expect("our frame");

    assert_eq!(&pkt.data[12..14], &[0x08, 0x00], "untagged data");
    let tag = VlanTag::new(100, VlanProto::Dot1Q);
    assert_eq!(pkt.stripped_vlan(), Some(tag));
    assert!(!pkt.status.vlan_reinserted);
    assert_eq!(pkt.view().rx_metadata.vlan, Some(tag));
    let f = vlan_filter(100, port);
    assert!(f.matches_with(&pkt.data, &pkt.bpf_ancillary()));
    assert!(
        !f.matches(&pkt.data),
        "offline the untagged frame has no tag"
    );
}

/// The transmitting side: the parent `A` sees the outgoing frames with the
/// tag in the metadata too (veth VLAN TX offload); they come out tagged.
#[test]
fn outgoing_frames_on_the_parent_are_tagged() {
    let Some(link) = VlanLink::create("t", 100) else {
        return;
    };
    let port = 44_000 + (std::process::id() % 1_000) as u16;
    let Some(mut cap) = open(
        Capture::builder()
            .interface(&link.veth.a)
            .block_timeout_ms(10)
            .poll_timeout(Duration::from_millis(50)),
    ) else {
        return;
    };
    inject(&link.vlan, port, 1);
    let pkt = first_ours(&mut cap).expect("our frame");
    assert_eq!(pkt.direction, PacketDirection::Outgoing);
    assert_eq!(&pkt.data[12..16], &[0x81, 0x00, 0x00, 0x64]);
}

/// A pcap written from the capture holds the tagged frame (what tcpdump /
/// Wireshark would have recorded).
#[cfg(feature = "pcap")]
#[test]
fn pcap_round_trip_keeps_the_tag() {
    use netring::pcap::CaptureWriter;
    use pcap_file::pcap::PcapReader;

    let Some(link) = VlanLink::create("p", 100) else {
        return;
    };
    let port = 45_000 + (std::process::id() % 1_000) as u16;
    let Some(mut cap) = open(
        Capture::builder()
            .interface(&link.veth.b)
            .block_timeout_ms(10)
            .poll_timeout(Duration::from_millis(50)),
    ) else {
        return;
    };
    inject(&link.vlan, port, 1);
    let mut writer = CaptureWriter::create(Vec::new()).expect("writer");
    {
        let mut pkts = cap.packets_for(Duration::from_secs(2));
        while let Some(pkt) = pkts.next_packet() {
            if is_ours(pkt.data()) {
                writer.write_packet(&pkt).expect("write");
                break;
            }
        }
    }
    let bytes = writer.into_inner();
    let mut reader = PcapReader::new(&bytes[..]).expect("reader");
    let rec = reader.next_packet().expect("a packet").expect("readable");
    assert_eq!(&rec.data[12..16], &[0x81, 0x00, 0x00, 0x64]);
    assert_eq!(rec.orig_len as usize, rec.data.len());
}

/// QinQ: an 802.1ad outer tag (100) on `A`, an 802.1Q inner tag (200) on
/// top. The kernel strips only the outer tag: `vlan_id(100)` matches it,
/// and userspace sees both tags back in place.
#[test]
fn qinq_outer_tag_is_reinserted_in_front_of_the_inner_one() {
    let pid = std::process::id() % 100_000;
    let Some(veth) = VethPair::create(&format!("s2q{pid}a"), &format!("s2q{pid}b")) else {
        eprintln!("skipping: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let (outer, inner) = (format!("s2q{pid}o"), format!("s2q{pid}i"));
    let ip = |args: &[&str]| {
        Command::new("ip")
            .args(args)
            .status()
            .is_ok_and(|s| s.success())
    };
    let ok = ip(&[
        "link", "add", "link", &veth.a, "name", &outer, "type", "vlan", "proto", "802.1ad", "id",
        "100",
    ]) && ip(&[
        "link", "add", "link", &outer, "name", &inner, "type", "vlan", "id", "200",
    ]) && ip(&["link", "set", &outer, "up"])
        && ip(&["link", "set", &inner, "up"]);
    let cleanup = || {
        let _ = Command::new("ip").args(["link", "delete", &inner]).output();
        let _ = Command::new("ip").args(["link", "delete", &outer]).output();
    };
    if !ok {
        cleanup();
        eprintln!("skipping: cannot create stacked 802.1ad / 802.1Q devices");
        return;
    }
    let port = 46_000 + (std::process::id() % 1_000) as u16;
    let filter = BpfFilter::builder()
        .vlan()
        .vlan_id(100)
        .build()
        .expect("filter");
    let Some(mut cap) = open(
        Capture::builder()
            .interface(&veth.b)
            .bpf_filter(filter)
            .block_timeout_ms(10)
            .poll_timeout(Duration::from_millis(50)),
    ) else {
        cleanup();
        return;
    };
    inject(&inner, port, 1);
    let pkt = first_ours(&mut cap);
    cleanup();
    let pkt = pkt.expect("vlan_id(100) matches the stripped outer tag");
    assert_eq!(
        &pkt.data[12..22],
        &[0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x08, 0x00]
    );
    assert_eq!(pkt.vlan, Some(VlanTag::new(100, VlanProto::Dot1Ad)));
}
