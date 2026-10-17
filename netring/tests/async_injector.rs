//! `AsyncInjector::send` on a full TX ring.
//!
//! Frames queued with `send` are only transmitted when the kernel is
//! kicked (`sendto`), so a ring full of queued frames never frees a slot on
//! its own: `send` has to kick before it waits for one.
//!
//! Requires CAP_NET_RAW. Run with:
//! cargo test --features integration-tests,tokio --test async_injector

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

use std::time::Duration;

use netring::{AsyncInjector, Injector};

/// More sends than the ring has frames, with no `flush` in between.
#[tokio::test]
async fn send_past_a_full_ring_does_not_hang() {
    let injector = Injector::builder()
        .interface("lo")
        .frame_count(8)
        .build()
        .expect("build injector");
    assert_eq!(injector.frame_count(), 8);
    let mut tx = AsyncInjector::new(injector).expect("wrap injector");

    let mut frame = [0u8; 64];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    let all = async {
        for _ in 0..32 {
            tx.send(&frame).await?;
        }
        tx.flush().await
    };
    let result = tokio::time::timeout(Duration::from_secs(2), all).await;
    result
        .expect("32 sends into an 8-frame ring hung")
        .expect("send / flush");
}

/// A dummy interface, up, whose root qdisc is `plug` — it holds every frame
/// until released, so the frames an injector sends stay in flight. Deleted
/// on drop.
struct PluggedDummy(String);

impl PluggedDummy {
    fn create() -> Option<Self> {
        use std::process::Command;
        let name = format!("nrplug{}", std::process::id() % 100_000);
        let _ = Command::new("ip").args(["link", "delete", &name]).output();
        let ok = |args: &[&str]| {
            Command::new("ip")
                .args(args)
                .status()
                .is_ok_and(|s| s.success())
        };
        if !ok(&["link", "add", &name, "type", "dummy"]) {
            return None;
        }
        let d = Self(name);
        if !ok(&["link", "set", &d.0, "up"]) {
            return None;
        }
        let ifindex = nix::net::if_::if_nametoindex(d.0.as_str()).ok()?;
        add_plug_qdisc(ifindex).ok()?;
        Some(d)
    }
}

impl Drop for PluggedDummy {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

/// `tc qdisc add dev <ifindex> root plug limit 1MiB`, over rtnetlink (no
/// `tc` binary needed). `plug` starts out holding (sch_plug: plug_init
/// throttles): every frame is queued until a release that never comes.
fn add_plug_qdisc(ifindex: u32) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
        let len = 4 + data.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(data);
        buf.resize(buf.len().next_multiple_of(4), 0);
    }

    const RTM_NEWQDISC: u16 = 36;
    const TCA_KIND: u16 = 1;
    const TCA_OPTIONS: u16 = 2;
    let mut body = Vec::new();
    // struct tcmsg { family: u8, pad: [u8; 3], ifindex: i32, handle: u32,
    // parent: u32, info: u32 }
    body.extend_from_slice(&[libc::AF_UNSPEC as u8, 0, 0, 0]);
    body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&0x0001_0000u32.to_ne_bytes()); // handle 1:
    body.extend_from_slice(&0xffff_ffffu32.to_ne_bytes()); // TC_H_ROOT
    body.extend_from_slice(&0u32.to_ne_bytes());
    attr(&mut body, TCA_KIND, b"plug\0");
    // struct tc_plug_qopt { action: i32 (TCQ_PLUG_BUFFER = 0), limit: u32 }
    let mut qopt = Vec::new();
    qopt.extend_from_slice(&0i32.to_ne_bytes());
    qopt.extend_from_slice(&(1u32 << 20).to_ne_bytes());
    attr(&mut body, TCA_OPTIONS, &qopt);

    let flags =
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    let mut msg = Vec::new();
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&RTM_NEWQDISC.to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&body);

    // SAFETY: plain syscalls on a fresh fd we own; buffers sized as passed.
    unsafe {
        let raw = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(raw);
        if libc::send(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ack = [0u8; 256];
        let n = libc::recv(fd.as_raw_fd(), ack.as_mut_ptr().cast(), ack.len(), 0);
        if n < 20 {
            return Err(std::io::Error::other("short netlink ack"));
        }
        // nlmsgerr: the error code follows the 16-byte header.
        let errno = i32::from_ne_bytes([ack[16], ack[17], ack[18], ack[19]]);
        if errno != 0 {
            return Err(std::io::Error::from_raw_os_error(-errno));
        }
    }
    Ok(())
}

/// #228: an async kick doesn't wait for the device. A flags-0 `sendto` on
/// a TX ring waits until every frame it handed over completes
/// (tpacket_snd(): `need_wait`), which a device that holds frames — here a
/// `plug` qdisc — may never do; `AsyncInjector::flush` made that blocking
/// call on the runtime thread. It now kicks with `MSG_DONTWAIT`.
#[tokio::test(flavor = "current_thread")]
async fn async_flush_does_not_wait_for_the_device() {
    let Some(dummy) = PluggedDummy::create() else {
        eprintln!("skip: cannot create a plugged dummy (needs CAP_NET_ADMIN, sch_plug)");
        return;
    };
    let injector = Injector::builder()
        .interface(&dummy.0)
        .frame_count(8)
        .build()
        .expect("build injector");
    let mut tx = AsyncInjector::new(injector).expect("wrap injector");
    let mut frame = [0u8; 64];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    for _ in 0..4 {
        tx.send(&frame).await.expect("queue");
    }
    // Releases the frames — by deleting the device — after 3 s, so a
    // blocking kick ends rather than hangs the test.
    let name = dummy.0.clone();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &name])
            .output();
    });
    let start = std::time::Instant::now();
    let kicked = tx.flush().await.expect("kick");
    let elapsed = start.elapsed();
    assert_eq!(kicked, 4);
    assert!(
        elapsed < Duration::from_secs(1),
        "flush waited {elapsed:?} for the device"
    );
    // Handed to the device, held by the qdisc: not drained.
    assert!(tx.pending_count() > 0, "frames are in flight");
    release.join().unwrap();
    drop(dummy);
}
