//! TX ring integrity end to end: every frame queued is delivered exactly
//! once, intact, and — unless a refused frame reorders them — in order,
//! under random mixes of allocate / send / dropped slots / non-blocking and
//! blocking kicks, with a qdisc that holds and drops (`tbf`) or none
//! (qdisc bypass, `ENOBUFS`), sync and async, `drop_rejected` on and off.
//! (Review r5's probes, kept as regression tests.)
//!
//! Requires root (CAP_NET_ADMIN + CAP_NET_RAW) and `tc`; each test creates
//! its own veth pair and skips without them. Run in a fresh netns:
//! cargo test --features integration-tests,tokio --test tx_integrity

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use netring::{AsyncInjector, Injector};

const ETYPE: u16 = 0x88b5;
const MAGIC: u32 = 0x5235_7235;

fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
fn tc(args: &[&str]) -> bool {
    Command::new("tc")
        .args(args)
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

struct Veth(String, String);
impl Veth {
    fn new(a: &str, b: &str, mtu: u32) -> Option<Self> {
        let _ = ip(&["link", "delete", a]);
        if !ip(&["link", "add", a, "type", "veth", "peer", "name", b]) {
            return None;
        }
        let v = Veth(a.into(), b.into());
        for i in [a, b] {
            if !ip(&["link", "set", i, "mtu", &mtu.to_string(), "up"]) {
                return None;
            }
        }
        Some(v)
    }
}
impl Drop for Veth {
    fn drop(&mut self) {
        let _ = ip(&["link", "delete", &self.0]);
    }
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn byte_at(seq: u64, i: usize) -> u8 {
    (seq.wrapping_mul(2654435761).wrapping_add(i as u64 * 31) >> 3) as u8
}

fn fill(buf: &mut [u8], seq: u64, len: usize) {
    buf[..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    buf[12..14].copy_from_slice(&ETYPE.to_be_bytes());
    buf[14..18].copy_from_slice(&MAGIC.to_be_bytes());
    buf[18..26].copy_from_slice(&seq.to_be_bytes());
    buf[26..28].copy_from_slice(&(len as u16).to_be_bytes());
    for (i, b) in buf[28..len].iter_mut().enumerate() {
        *b = byte_at(seq, i);
    }
}

fn frame(seq: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    fill(&mut v, seq, len);
    v
}

/// (seq, intact)
fn parse(buf: &[u8]) -> Option<(u64, bool)> {
    if buf.len() < 28 || buf[12..14] != ETYPE.to_be_bytes() || buf[14..18] != MAGIC.to_be_bytes() {
        return None;
    }
    let seq = u64::from_be_bytes(buf[18..26].try_into().unwrap());
    let len = u16::from_be_bytes(buf[26..28].try_into().unwrap()) as usize;
    let ok = len == buf.len()
        && buf[28..]
            .iter()
            .enumerate()
            .all(|(i, &b)| b == byte_at(seq, i));
    Some((seq, ok))
}

fn ifindex(name: &str) -> i32 {
    let c = std::ffi::CString::new(name).unwrap();
    unsafe { libc::if_nametoindex(c.as_ptr()) as i32 }
}

/// What a receiver saw: `(seq, intact)` per frame, and the socket's drops.
type Received = (Vec<(u64, bool)>, u32);

/// Raw receiver on `iface`, collecting in a thread.
struct Rx {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<Received>>,
}

impl Rx {
    fn start(iface: &str) -> Self {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        assert!(fd >= 0, "rx socket");
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let sz: libc::c_int = 256 << 20;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                (&sz as *const libc::c_int).cast(),
                4,
            )
        };
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex(iface);
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&sll as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        assert_eq!(rc, 0, "bind rx");
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = vec![0u8; 65536];
            let mut quiet_since: Option<Instant> = None;
            loop {
                let mut pfd = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, 20) };
                let mut any = false;
                loop {
                    let n = unsafe {
                        libc::recv(
                            fd.as_raw_fd(),
                            buf.as_mut_ptr().cast(),
                            buf.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                    any = true;
                    if let Some(p) = parse(&buf[..n as usize]) {
                        got.push(p);
                    }
                }
                if any {
                    quiet_since = None;
                }
                if s.load(Ordering::Relaxed) {
                    let q = *quiet_since.get_or_insert_with(Instant::now);
                    if q.elapsed() > Duration::from_millis(300) {
                        break;
                    }
                }
            }
            // PACKET_STATISTICS: tp_packets, tp_drops
            let mut st = [0u32; 2];
            let mut len: libc::socklen_t = 8;
            unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    st.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            (got, st[1])
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Received {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap()
    }
}

/// Compare what arrived with what was expected, in order.
fn check(
    label: &str,
    expected: &[u64],
    got: &[(u64, bool)],
    rx_drops: u32,
    strict_order: bool,
) -> Result<(), String> {
    let strict_order = strict_order && std::env::var("R5_LOOSE").is_err();
    let corrupt: Vec<_> = got.iter().filter(|(_, ok)| !ok).map(|(s, _)| *s).collect();
    let seqs: Vec<u64> = got.iter().map(|(s, _)| *s).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    let mut dups = Vec::new();
    for w in sorted.windows(2) {
        if w[0] == w[1] {
            dups.push(w[0]);
        }
    }
    let exp_set: std::collections::BTreeSet<u64> = expected.iter().copied().collect();
    let got_set: std::collections::BTreeSet<u64> = seqs.iter().copied().collect();
    let missing: Vec<_> = exp_set.difference(&got_set).copied().collect();
    let extra: Vec<_> = got_set.difference(&exp_set).copied().collect();
    let in_order = seqs.windows(2).filter(|w| w[0] > w[1]).count();
    let msg = format!(
        "{label}: expected {} got {} rx_drops {rx_drops} missing {} {:?} extra {:?} dups {} {:?} corrupt {} {:?} reorders {in_order}",
        expected.len(),
        seqs.len(),
        missing.len(),
        &missing[..missing.len().min(10)],
        &extra[..extra.len().min(10)],
        dups.len(),
        &dups[..dups.len().min(10)],
        corrupt.len(),
        &corrupt[..corrupt.len().min(10)],
    );
    eprintln!("{msg}");
    if !missing.is_empty()
        || !extra.is_empty()
        || !dups.is_empty()
        || !corrupt.is_empty()
        || (strict_order && in_order > 0)
    {
        return Err(msg);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Cfg {
    frame_size: usize,
    frame_count: usize,
    mtu: u32,
    steps: usize,
    seed: u64,
    blocking: bool,
    drop_rejected: bool,
    qdisc_bypass: bool,
}

/// Sync Injector op mix.
fn run_sync(tx_if: &str, rx_if: &str, cfg: Cfg) -> Result<(), String> {
    let rx = Rx::start(rx_if);
    std::thread::sleep(Duration::from_millis(50));
    let mut tx = Injector::builder()
        .interface(tx_if)
        .frame_size(cfg.frame_size)
        .frame_count(cfg.frame_count)
        .drop_rejected(cfg.drop_rejected)
        .qdisc_bypass(cfg.qdisc_bypass)
        .build()
        .map_err(|e| e.to_string())?;
    let cap = tx.frame_capacity();
    let max_ok = (cfg.mtu as usize + 14).min(cap);
    let mut rng = XorShift(cfg.seed | 1);
    let mut seq = 0u64;
    let mut expected = Vec::new();
    let mut errors = 0usize;
    let mut stalls = 0usize;
    for _ in 0..cfg.steps {
        let r = rng.below(100);
        if r < 70 {
            let oversize = cap > max_ok && rng.below(40) == 0;
            let len = if oversize {
                max_ok + 1 + rng.below((cap - max_ok) as u64) as usize
            } else {
                60 + rng.below((max_ok - 60 + 1) as u64) as usize
            };
            let dropit = rng.below(10) == 0;
            let queued = if let Some(mut slot) = tx.allocate(len) {
                if dropit {
                    // write junk, then discard
                    slot.data_mut()[..len].fill(0xee);
                    drop(slot);
                    continue;
                }
                fill(slot.data_mut(), seq, len);
                slot.set_len(len);
                slot.send();
                true
            } else {
                false
            };
            if queued {
                if !oversize {
                    expected.push(seq);
                }
                seq += 1;
            } else {
                stalls += 1;
                if tx.flush_nonblocking().is_err() {
                    errors += 1;
                }
                std::thread::sleep(Duration::from_micros(200));
            }
        } else if r < 96 || !cfg.blocking {
            if tx.flush_nonblocking().is_err() {
                errors += 1;
            }
        } else if tx.flush().is_err() {
            errors += 1;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while (tx.queued_count() > 0 || tx.pending_count() > 0) && Instant::now() < deadline {
        if tx.flush_nonblocking().is_err() {
            errors += 1;
        }
        if !cfg.drop_rejected && tx.queued_count() > 0 {
            // frames held behind a refused slot: fill the ring until it wraps
            let queued = if let Some(mut slot) = tx.allocate(100) {
                fill(slot.data_mut(), seq, 100);
                slot.set_len(100);
                slot.send();
                true
            } else {
                false
            };
            if queued {
                expected.push(seq);
                seq += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let (q, p) = (tx.queued_count(), tx.pending_count());
    let (got, drops) = rx.finish();
    eprintln!("cfg {cfg:?}: sent {seq} errors {errors} stalls {stalls} queued {q} pending {p}");
    if q != 0 || p != 0 {
        return Err(format!("stranded: queued_count {q} pending_count {p}"));
    }
    check("sync", &expected, &got, drops, cfg.drop_rejected)
}

/// Install a root qdisc; `false` when `tc` can't (no binary, no module).
fn setup_qdisc(dev: &str, kind: &str) -> bool {
    let _ = tc(&["qdisc", "del", "dev", dev, "root"]);
    match kind {
        "tbf" => tc(&[
            "qdisc", "add", "dev", dev, "root", "tbf", "rate", "40mbit", "burst", "6kb", "limit",
            "8kb",
        ]),
        "none" => true,
        _ => false,
    }
}

fn sync_matrix(qdisc: &str, bypass: bool) {
    let mut failures = Vec::new();
    let geoms = [
        (2048usize, 16usize, 1500u32),
        (1360, 7, 1300),
        (3008, 5, 1500),
    ];
    for (gi, &(fs, fc, mtu)) in geoms.iter().enumerate() {
        for seed in 1..=2u64 {
            let a = format!("r5s{gi}{seed}a");
            let b = format!("r5s{gi}{seed}b");
            let Some(_v) = Veth::new(&a, &b, mtu) else {
                eprintln!("skip: no veth");
                return;
            };
            if !setup_qdisc(&a, qdisc) {
                eprintln!("skip: no tc / {qdisc}");
                return;
            }
            let cfg = Cfg {
                frame_size: fs,
                frame_count: fc,
                mtu,
                steps: 3000,
                seed: seed * 7919 + gi as u64,
                blocking: true,
                drop_rejected: true,
                qdisc_bypass: bypass,
            };
            if let Err(e) = run_sync(&a, &b, cfg) {
                failures.push(format!("{cfg:?}: {e}"));
            }
            if let Ok(o) = Command::new("tc")
                .args(["-s", "qdisc", "show", "dev", &a])
                .output()
            {
                let t = String::from_utf8_lossy(&o.stdout);
                eprintln!("qdisc: {}", t.lines().nth(1).unwrap_or(""));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn r5_sync_tbf() {
    sync_matrix("tbf", false);
}

// No `netem` matrix: a netem qdisc with a delay orphans each packet on
// enqueue (`skb_orphan_partial`), which runs the TX ring's skb destructor
// and hands the slot back while the queued skb still points at its pages —
// a frame queued in the slot then overwrites one netem hasn't sent yet. A
// kernel behaviour no ring bookkeeping can avoid (see `Injector`'s docs).

#[test]
fn r5_sync_noqueue_bypass() {
    sync_matrix("none", true);
}

/// Async adapter op mix: send / flush / dropped slots via get_mut.
async fn run_async(tx_if: &str, rx_if: &str, cfg: Cfg) -> Result<(), String> {
    let rx = Rx::start(rx_if);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let inj = Injector::builder()
        .interface(tx_if)
        .frame_size(cfg.frame_size)
        .frame_count(cfg.frame_count)
        .drop_rejected(cfg.drop_rejected)
        .qdisc_bypass(cfg.qdisc_bypass)
        .build()
        .map_err(|e| e.to_string())?;
    let mut tx = AsyncInjector::new(inj).map_err(|e| e.to_string())?;
    let cap = tx.frame_capacity();
    let max_ok = (cfg.mtu as usize + 14).min(cap);
    let mut rng = XorShift(cfg.seed | 1);
    let mut seq = 0u64;
    let mut expected = Vec::new();
    let mut errors = 0;
    for _ in 0..cfg.steps {
        let r = rng.below(100);
        if r < 70 {
            let oversize = cap > max_ok && rng.below(40) == 0;
            let len = if oversize {
                max_ok + 1 + rng.below((cap - max_ok) as u64) as usize
            } else {
                60 + rng.below((max_ok - 60 + 1) as u64) as usize
            };
            let f = frame(seq, len);
            let res = tokio::time::timeout(Duration::from_secs(5), tx.send(&f)).await;
            match res {
                Err(_) => return Err(format!("send hung at seq {seq}")),
                Ok(Err(e)) => {
                    errors += 1;
                    eprintln!("send err {e}");
                    continue;
                }
                Ok(Ok(())) => {}
            }
            if !oversize {
                expected.push(seq);
            }
            seq += 1;
        } else if r < 80 {
            if let Some(slot) = tx.get_mut().allocate(100) {
                drop(slot);
            }
        } else if tx.flush().await.is_err() {
            errors += 1;
        }
    }
    let _ = tx.flush().await;
    let res = tx.wait_drained(Duration::from_secs(20)).await;
    let (q, p) = (tx.get_ref().queued_count(), tx.pending_count());
    let (got, drops) = rx.finish();
    eprintln!(
        "async cfg {cfg:?}: sent {seq} errors {errors} drained {res:?} queued {q} pending {p}"
    );
    if res.is_err() {
        return Err(format!("wait_drained {res:?} queued {q} pending {p}"));
    }
    check("async", &expected, &got, drops, cfg.drop_rejected)
}

#[tokio::test(flavor = "current_thread")]
async fn r5_async_tbf_and_bypass() {
    let mut failures = Vec::new();
    for (qi, qdisc) in ["tbf", "none"].iter().enumerate() {
        for (gi, &(fs, fc, mtu)) in [(2048usize, 16usize, 1500u32), (1360, 7, 1300)]
            .iter()
            .enumerate()
        {
            let a = format!("r5a{qi}{gi}a");
            let b = format!("r5a{qi}{gi}b");
            let Some(_v) = Veth::new(&a, &b, mtu) else {
                eprintln!("skip: no veth");
                return;
            };
            if !setup_qdisc(&a, qdisc) {
                eprintln!("skip: no tc / {qdisc}");
                return;
            }
            let cfg = Cfg {
                frame_size: fs,
                frame_count: fc,
                mtu,
                steps: 3000,
                seed: 31 * (qi as u64 + 1) + gi as u64,
                blocking: false,
                drop_rejected: true,
                qdisc_bypass: *qdisc == "none",
            };
            if let Err(e) = run_async(&a, &b, cfg).await {
                failures.push(format!("{qdisc} {cfg:?}: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Review r5: with `drop_rejected(false)`, refilling the refused slot left
/// the injector's cursor one past the kernel's TX position: frames were
/// stranded while reported sent, and a second refusal wedged `allocate`
/// for good. Exactly-once delivery under a random op mix with refusals.
#[test]
fn r5_sync_rejected_false() {
    let mut failures = Vec::new();
    for (gi, &(fs, fc, mtu)) in [
        (2048usize, 16usize, 1500u32),
        (1360, 7, 1300),
        (1536, 9, 1400),
    ]
    .iter()
    .enumerate()
    {
        for seed in 1..=3u64 {
            let a = format!("r5f{gi}{seed}a");
            let b = format!("r5f{gi}{seed}b");
            let Some(_v) = Veth::new(&a, &b, mtu) else {
                eprintln!("skip: no veth");
                return;
            };
            if !setup_qdisc(&a, "tbf") {
                eprintln!("skip: no tc / tbf");
                return;
            }
            let cfg = Cfg {
                frame_size: fs,
                frame_count: fc,
                mtu,
                steps: 4000,
                seed: seed * 104729 + gi as u64,
                blocking: true,
                drop_rejected: false,
                qdisc_bypass: false,
            };
            if let Err(e) = run_sync(&a, &b, cfg) {
                failures.push(format!("{cfg:?}: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ── Refused frames (`drop_rejected(false)`) ────────────────────────────────

/// A frame with `seq` at bytes 14..22.
fn seq_frame(seq: u64, len: usize) -> Vec<u8> {
    let mut f = vec![0x5au8; len];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 9]);
    f[12..14].copy_from_slice(&ETYPE.to_be_bytes());
    f[14..22].copy_from_slice(&seq.to_be_bytes());
    f
}

/// A non-blocking receiver of `ETYPE` frames on `iface`.
fn rx_socket(iface: &str) -> OwnedFd {
    // SAFETY: plain socket(2).
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK,
            ETYPE.to_be() as i32,
        )
    };
    assert!(fd >= 0);
    // SAFETY: a fresh fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zeroed sockaddr_ll is valid; bind reads it.
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ETYPE.to_be();
    sll.sll_ifindex = ifindex(iface);
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&sll as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    assert_eq!(rc, 0);
    fd
}

/// The sequence numbers received on `fd` within `wait`.
fn recv_seqs(fd: &OwnedFd, wait: Duration) -> Vec<u64> {
    let mut out = Vec::new();
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        // SAFETY: recv into a buffer we own.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n >= 22 {
            out.push(u64::from_be_bytes(buf[14..22].try_into().unwrap()));
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    out
}

fn try_queue(tx: &mut Injector, seq: u64, len: usize) -> bool {
    match tx.allocate(len) {
        Some(mut s) => {
            s.data_mut()[..len].copy_from_slice(&seq_frame(seq, len));
            s.set_len(len);
            s.send();
            true
        }
        None => false,
    }
}

fn queue(tx: &mut Injector, seq: u64, len: usize) {
    assert!(try_queue(tx, seq, len), "no slot for seq {seq}");
}

/// Review r5: the refused slot, handed out when the ring wraps, refused
/// again: `allocate` never returned a slot again.
#[test]
fn r5_refused_twice_wedges_allocate() {
    let Some(v) = Veth::new("r5wh0", "r5wh1", 1500) else {
        eprintln!("skip: no veth");
        return;
    };
    let mut tx = Injector::builder()
        .interface(&v.0)
        .frame_count(4)
        .drop_rejected(false)
        .build()
        .unwrap();
    queue(&mut tx, 100, 1600); // refused
    for s in 1..4 {
        queue(&mut tx, s, 100);
    }
    assert!(tx.flush_nonblocking().is_err(), "EMSGSIZE");
    assert!(
        try_queue(&mut tx, 101, 1600),
        "the refused slot is handed out"
    );
    assert!(tx.flush_nonblocking().is_err(), "refused again");
    let start = Instant::now();
    let mut ok = false;
    while start.elapsed() < Duration::from_secs(2) {
        let _ = tx.flush_nonblocking();
        if try_queue(&mut tx, 4, 100) {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        ok,
        "allocate never returns a slot again (queued {}, pending {}, rejected {})",
        tx.queued_count(),
        tx.pending_count(),
        tx.rejected_slots()
    );
}

/// Review r5: after the refill of a refused slot, the next frame landed
/// past the kernel's TX position — reported taken while it stayed queued,
/// so `wait_drained` timed out and it left only when the ring wrapped.
#[test]
fn r5_refused_slot_refill_keeps_the_cursor_in_step() {
    let Some(v) = Veth::new("r5wf0", "r5wf1", 1500) else {
        eprintln!("skip: no veth");
        return;
    };
    let rx = rx_socket(&v.1);
    std::thread::sleep(Duration::from_millis(100));
    let mut tx = Injector::builder()
        .interface(&v.0)
        .frame_count(4)
        .drop_rejected(false)
        .build()
        .unwrap();
    const BIG: usize = 1600;
    queue(&mut tx, 100, BIG);
    for s in 1..4 {
        queue(&mut tx, s, 100);
    }
    assert!(tx.flush_nonblocking().is_err(), "EMSGSIZE");
    // The ring wrapped: the refused slot is refilled, and goes first.
    queue(&mut tx, 4, 100);
    assert_eq!(tx.flush_nonblocking().unwrap(), 4);
    tx.wait_drained(Duration::from_secs(1)).unwrap();
    assert_eq!(recv_seqs(&rx, Duration::from_millis(100)), [4, 1, 2, 3]);
    // One more frame: sent at once, not stranded.
    queue(&mut tx, 5, 100);
    assert_eq!(tx.flush_nonblocking().unwrap(), 1);
    assert_eq!(tx.queued_count(), 0);
    tx.wait_drained(Duration::from_millis(300))
        .expect("the frame leaves");
    assert_eq!(recv_seqs(&rx, Duration::from_millis(100)), [5]);
}

/// Review r5: the same through `AsyncInjector` — `send` never completed
/// after two refusals.
#[tokio::test(flavor = "current_thread")]
async fn r5_async_send_survives_two_refusals() {
    let Some(v) = Veth::new("r5wg0", "r5wg1", 1500) else {
        eprintln!("skip: no veth");
        return;
    };
    let mut tx = AsyncInjector::new(
        Injector::builder()
            .interface(&v.0)
            .frame_count(4)
            .drop_rejected(false)
            .build()
            .unwrap(),
    )
    .unwrap();
    const BIG: usize = 1600;
    let plan: &[(u64, usize, bool)] = &[
        // (seq, len, flush after)
        (100, BIG, false),
        (1, 100, false),
        (2, 100, false),
        (3, 100, true),
        (4, 100, true),
        (5, 100, false),
        (6, 100, false),
        (101, BIG, false),
        (7, 100, true),
        (8, 100, false),
        (9, 100, false),
        (102, BIG, true),
        (10, 100, false),
        (11, 100, false),
        (12, 100, false),
        (13, 100, false),
    ];
    for &(seq, len, flush) in plan {
        let r = tokio::time::timeout(Duration::from_secs(3), tx.send(&seq_frame(seq, len))).await;
        assert!(
            r.is_ok(),
            "send of seq {seq} hung (queued_count {}, pending_count {}, rejected {})",
            tx.get_ref().queued_count(),
            tx.pending_count(),
            tx.rejected_slots()
        );
        if flush {
            let _ = tx.flush().await;
            let _ = tx.wait_drained(Duration::from_millis(200)).await;
        }
    }
}
