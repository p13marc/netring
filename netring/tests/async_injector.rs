//! `AsyncInjector::send` on a full TX ring.
//!
//! Frames queued with `send` are only transmitted when the kernel is
//! kicked (`sendto`), so a ring full of queued frames never frees a slot on
//! its own: `send` has to kick before it waits for one.
//!
//! Requires CAP_NET_RAW. Run with:
//! cargo test --features integration-tests,tokio --test async_injector

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

mod helpers;

use std::time::Duration;

use helpers::PluggedDummy;
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

/// A frame `send` can queue (broadcast, local experimental EtherType).
fn tx_frame(len: usize) -> Vec<u8> {
    let mut frame = vec![0u8; len];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    frame
}

/// CPU time this thread has used.
fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// #228 review: `send` on a full ring whose kick can hand nothing over (the
/// socket's send buffer is full of frames the device holds) retried the
/// kick at once, forever: the task never yielded, so nothing else on its
/// runtime ran — not even the timeout around it. It now waits for the
/// device. `send_stream` (send + flush per frame) on a plugged dummy, inside
/// a 2 s tokio timeout, next to a 10 ms ticker on the same current-thread
/// runtime.
#[test]
fn send_on_a_device_that_holds_frames_yields() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let Some(dummy) = PluggedDummy::create_named("nrtxhold0") else {
        eprintln!("skip: cannot create a plugged dummy (needs CAP_NET_ADMIN, sch_plug)");
        return;
    };
    let name = dummy.0.clone();
    let ticks = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let (t2, d2) = (Arc::clone(&ticks), Arc::clone(&done));
    let worker = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    t2.fetch_add(1, Ordering::Relaxed);
                }
            });
            let inj = Injector::builder()
                .interface(&name)
                .frame_count(256)
                .frame_size(2048)
                .build()
                .expect("injector");
            let mut tx = AsyncInjector::new(inj).expect("wrap");
            let frames = futures::stream::iter((0..1000).map(|_| tx_frame(1400)));
            let res =
                tokio::time::timeout(Duration::from_secs(2), tx.send_stream(frames, None)).await;
            assert!(
                res.is_err(),
                "the device holds every frame: the stream can't finish"
            );
            d2.store(true, Ordering::SeqCst);
        });
    });
    std::thread::sleep(Duration::from_millis(500));
    let t0 = ticks.load(Ordering::Relaxed);
    let start = std::time::Instant::now();
    while !done.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(4) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let (finished, t1) = (done.load(Ordering::SeqCst), ticks.load(Ordering::Relaxed));
    // Unblock a spinning worker either way: let the frames go, then remove
    // the device.
    let _ = dummy.release();
    std::thread::sleep(Duration::from_millis(200));
    drop(dummy);
    let joined = worker.join();
    assert!(
        finished,
        "the 2 s timeout around send_stream never fired: send spun"
    );
    assert!(
        t1 > t0,
        "the runtime's ticker never ran: send never yielded"
    );
    joined.expect("worker");
}

/// #228 review: a non-blocking kick the send buffer cuts short hands over
/// some frames and leaves the rest queued — but it zeroed the injector's
/// queued count, so later flushes kicked nothing and the rest stayed queued
/// for good (`wait_drained` timed out, drop didn't kick them). The count now
/// comes from the ring.
#[tokio::test(flavor = "current_thread")]
async fn a_kick_cut_short_is_kicked_again() {
    let Some(dummy) = PluggedDummy::create_named("nrtxkick0") else {
        eprintln!("skip: cannot create a plugged dummy (needs CAP_NET_ADMIN, sch_plug)");
        return;
    };
    let injector = Injector::builder()
        .interface(&dummy.0)
        .frame_count(256)
        .frame_size(2048)
        .build()
        .expect("build injector");
    let mut tx = AsyncInjector::new(injector).expect("wrap");
    let frame = tx_frame(1400);
    for _ in 0..200 {
        tx.send(&frame).await.expect("queue");
    }
    // The send buffer holds far fewer than 200 such frames: this kick is
    // cut short, and the plug holds what it took.
    tx.flush().await.expect("kick");
    dummy.release().expect("release the plug");
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Kick what the first one couldn't hand over.
    tx.flush().await.expect("kick again");
    let res = tx.wait_drained(Duration::from_secs(3)).await;
    assert!(
        res.is_ok(),
        "frames stranded in the ring: {res:?}, pending {}",
        tx.pending_count()
    );
}

/// #228 review: with `tx_timestamps(true)` the socket's error queue holds a
/// timestamp per sent frame, so epoll reports `EPOLLOUT | EPOLLERR`, which
/// tokio keeps as a sticky write-closed readiness: every writability wait
/// resolved at once, and `wait_drained` / `send` on a full ring spun. They
/// poll the ring every millisecond in that state instead.
#[tokio::test(flavor = "current_thread")]
async fn tx_waits_dont_spin_with_tx_timestamps() {
    let Some(dummy) = PluggedDummy::create_named("nrtxts0") else {
        eprintln!("skip: cannot create a plugged dummy (needs CAP_NET_ADMIN, sch_plug)");
        return;
    };
    // Through the qdisc once, with the plug released: its timestamp lands on
    // the error queue. Then plug again.
    dummy.release().expect("release");
    let inj = Injector::builder()
        .interface(&dummy.0)
        .frame_count(16)
        .tx_timestamps(true)
        .build()
        .expect("injector");
    let mut tx = AsyncInjector::new(inj).expect("wrap");
    tx.send(&tx_frame(64)).await.unwrap();
    tx.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    dummy.block().expect("plug again");

    for _ in 0..4 {
        tx.send(&tx_frame(64)).await.unwrap();
    }
    tx.flush().await.unwrap();
    assert!(tx.pending_count() > 0, "the plug holds them");
    let c0 = thread_cpu();
    let res = tx.wait_drained(Duration::from_secs(1)).await;
    let used = thread_cpu() - c0;
    assert!(res.is_err(), "held frames can't drain");
    assert!(
        used < Duration::from_millis(300),
        "wait_drained spun: {used:?} CPU in 1 s"
    );

    // Fill the ring, then a send that has to wait.
    let mut queued = 0;
    while tx.get_ref().available_slots() > 0 && queued < 64 {
        tx.send(&tx_frame(64)).await.unwrap();
        queued += 1;
    }
    tx.flush().await.unwrap();
    let c0 = thread_cpu();
    let res = tokio::time::timeout(Duration::from_secs(1), tx.send(&tx_frame(64))).await;
    let used = thread_cpu() - c0;
    assert!(res.is_err(), "no slot frees while the plug holds them");
    assert!(
        used < Duration::from_millis(300),
        "send spun: {used:?} CPU in 1 s"
    );
}

/// Review r3: with `drop_rejected(false)` the kernel leaves a refused
/// frame's slot `WRONG_FORMAT` and its TX position on it. `allocate` reset
/// that slot but didn't hand it out, so the frames queued after it could
/// never leave: `send` kicked (nothing to hand over: the kernel's position
/// sits on a now-empty slot) and waited for a writability edge that never
/// came — with a free slot in the ring. The reset slot is handed out now.
#[tokio::test(flavor = "current_thread")]
async fn send_reuses_the_slot_of_a_refused_frame() {
    let Some(dummy) = helpers::Dummy::create("nrtxwf0", Some(68)) else {
        eprintln!("skip: cannot create a dummy (needs CAP_NET_ADMIN)");
        return;
    };
    let inj = Injector::builder()
        .interface(&dummy.0)
        .frame_count(4)
        .drop_rejected(false)
        .build()
        .expect("injector");
    let mut tx = AsyncInjector::new(inj).expect("wrap");
    // 200 bytes don't fit a 68-byte MTU: the kick stops there.
    for len in [60, 200, 60, 60] {
        tx.send(&tx_frame(len)).await.expect("queue");
    }
    let err = tx.flush().await.expect_err("EMSGSIZE");
    assert!(
        matches!(&err, netring::Error::Io(e) if e.raw_os_error() == Some(libc::EMSGSIZE)),
        "{err}"
    );
    assert_eq!(tx.get_ref().rejected_slots(), 1);
    // The two frames after the refused one wait for its slot.
    assert!(tx.wait_drained(Duration::from_millis(100)).await.is_err());
    tx.send(&tx_frame(60))
        .await
        .expect("the first sent frame's slot");
    let res = tokio::time::timeout(Duration::from_secs(2), tx.send(&tx_frame(60))).await;
    res.expect("send waited for a slot the ring had")
        .expect("send");
    // Queued in the refused slot, they all leave on the next kick.
    tx.flush().await.expect("kick");
    tx.wait_drained(Duration::from_secs(2))
        .await
        .expect("every frame leaves");
}
