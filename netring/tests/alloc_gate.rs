//! Measured allocation gate (#170) over the real pipeline: pcap frames
//! → `AsyncPcapSource` → flowscope engine → `Monitor` handlers /
//! `PcapSessionStream`.
//!
//! The pcap source owns each packet it reads (one buffer per packet,
//! by design: the reader runs on a blocking thread). Everything after
//! it — tracking, reassembly, parsing, dispatch — must allocate
//! nothing per packet in steady state. Measured as the *marginal*
//! allocations per packet (a 2N-packet run minus an N-packet run, so
//! setup cost cancels) of the full pipeline minus the source's own.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{SessionParser, Timestamp};
use futures::StreamExt;
use netring::AsyncPcapSource;
use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::{FlowEnded, FlowPacket, FlowStarted};
use tempfile::NamedTempFile;

struct Counting;

static ON: AtomicBool = AtomicBool::new(false);
static BLOCKS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ON.load(Ordering::Relaxed) {
            BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if ON.load(Ordering::Relaxed) {
            BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Allocations (all threads) while `f` runs.
async fn counted<F: std::future::Future<Output = ()>>(f: F) -> u64 {
    BLOCKS.store(0, Ordering::SeqCst);
    ON.store(true, Ordering::SeqCst);
    f.await;
    ON.store(false, Ordering::SeqCst);
    BLOCKS.load(Ordering::SeqCst)
}

/// One TCP connection: handshake, then `n` request/response segment
/// pairs in order, then the FIN exchange. `2n + 6` frames.
fn pcap(n: usize) -> (NamedTempFile, usize) {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let m = [0u8; 6];
    let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let (mut cseq, mut sseq) = (1000u32, 5000u32);
    let mut v = vec![
        ipv4_tcp(m, m, c, s, 40_000, 80, cseq, 0, 0x02, b""),
        ipv4_tcp(m, m, s, c, 80, 40_000, sseq, cseq + 1, 0x12, b""),
    ];
    cseq += 1;
    sseq += 1;
    v.push(ipv4_tcp(m, m, c, s, 40_000, 80, cseq, sseq, 0x10, b""));
    let (req, resp) = ([b'q'; 200], [b'r'; 1200]);
    for _ in 0..n {
        v.push(ipv4_tcp(m, m, c, s, 40_000, 80, cseq, sseq, 0x18, &req));
        cseq += req.len() as u32;
        v.push(ipv4_tcp(m, m, s, c, 80, 40_000, sseq, cseq, 0x18, &resp));
        sseq += resp.len() as u32;
    }
    v.push(ipv4_tcp(m, m, c, s, 40_000, 80, cseq, sseq, 0x11, b""));
    v.push(ipv4_tcp(m, m, s, c, 80, 40_000, sseq, cseq + 1, 0x11, b""));
    v.push(ipv4_tcp(
        m,
        m,
        c,
        s,
        40_000,
        80,
        cseq + 1,
        sseq + 1,
        0x10,
        b"",
    ));
    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (i, f) in v.iter().enumerate() {
        let ts = Duration::from_secs(1) + Duration::from_micros(50 * i as u64);
        w.write_packet(&PcapPacket::new(ts, f.len() as u32, f))
            .unwrap();
    }
    (file, v.len())
}

async fn source_only(path: &std::path::Path) {
    let mut src = AsyncPcapSource::open(path).await.unwrap();
    while let Some(p) = src.next().await {
        std::hint::black_box(p.unwrap());
    }
}

async fn monitor(path: &std::path::Path) {
    Monitor::builder()
        .pcap_source(path)
        .protocol::<Tcp>()
        .on::<FlowStarted<Tcp>>(|_: &FlowStarted<Tcp>| Ok(()))
        .on::<FlowPacket>(|p: &FlowPacket| {
            std::hint::black_box(p.len);
            Ok(())
        })
        .on::<FlowEnded<Tcp>>(|_: &FlowEnded<Tcp>| Ok(()))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
}

#[derive(Clone, Default)]
struct Silent;

impl SessionParser for Silent {
    type Message = ();
    fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
}

async fn sessions(path: &std::path::Path) {
    let mut s = AsyncPcapSource::open(path)
        .await
        .unwrap()
        .sessions(FiveTuple::bidirectional(), Silent);
    while let Some(e) = s.next().await {
        std::hint::black_box(e.unwrap());
    }
}

/// Marginal allocations per packet of `run`: (2N run − N run) / N.
async fn marginal<F, Fut>(run: F) -> f64
where
    F: Fn(std::path::PathBuf) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    const N: usize = 2_000;
    let (small, small_len) = pcap(N);
    let (large, large_len) = pcap(2 * N);
    // Warm lazy statics (tracing, runtime internals) once.
    run(small.path().to_owned()).await;
    let a = counted(run(small.path().to_owned())).await;
    let b = counted(run(large.path().to_owned())).await;
    (b as f64 - a as f64) / (large_len - small_len) as f64
}

#[tokio::test(flavor = "current_thread")]
async fn engine_and_dispatch_add_no_allocations_per_packet() {
    let src = marginal(|p| async move { source_only(&p).await }).await;
    let mon = marginal(|p| async move { monitor(&p).await }).await;
    let ses = marginal(|p| async move { sessions(&p).await }).await;
    eprintln!("allocations per packet: source {src:.3}, monitor {mon:.3}, session stream {ses:.3}");
    // A few hundredths of slack for amortised growth (channel blocks).
    assert!(mon - src < 0.05, "Monitor adds {:.3}/packet", mon - src);
    assert!(
        ses - src < 0.05,
        "PcapSessionStream adds {:.3}/packet",
        ses - src
    );
}
