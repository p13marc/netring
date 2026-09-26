//! Monitor lifecycle on replay: sweeps (idle `FlowEnded` mid-replay,
//! #156), per-flow state release (#162), messages before their flow's
//! end (#163), and outputs flushed at exit (#169).

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "http"
))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::EndReason;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use netring::anomaly::sink::AnomalySink;
use netring::monitor::Monitor;
use netring::protocol::builtin::{Http, Tcp, Udp};
use netring::protocol::event_typed::{FlowEnded, FlowStarted};
use tempfile::NamedTempFile;

fn pcap(frames: &[(Duration, Vec<u8>)]) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (ts, f) in frames {
        w.write_packet(&PcapPacket::new_owned(*ts, f.len() as u32, f.clone()))
            .unwrap();
    }
    file
}

fn udp(src_port: u16, t_secs: u64) -> (Duration, Vec<u8>) {
    (
        Duration::from_secs(t_secs),
        ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], src_port, 53, b"query"),
    )
}

type Log = Arc<Mutex<Vec<String>>>;

/// #156: a flow that goes quiet ends on packet time, before later
/// traffic — not only at the end of the file.
#[tokio::test(flavor = "current_thread")]
async fn idle_flows_end_mid_replay_in_time_order() {
    // UDP idle timeout is 60 s: flow A (port 5000) is idle long before
    // flow B (port 6000) shows up.
    let file = pcap(&[udp(5000, 1), udp(6000, 200)]);
    let log: Log = Arc::default();
    let (l1, l2) = (Arc::clone(&log), Arc::clone(&log));
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |e: &FlowStarted<Udp>| {
            l1.lock().unwrap().push(format!(
                "start {}",
                e.key.a.port().min(e.key.b.port()).max(5000)
            ));
            Ok(())
        })
        .on::<FlowEnded<Udp>>(move |e: &FlowEnded<Udp>| {
            let port = e.key.a.port().max(e.key.b.port());
            l2.lock()
                .unwrap()
                .push(format!("end {port} {:?}", e.reason));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let log = log.lock().unwrap().clone();
    assert_eq!(log.len(), 4, "{log:?}");
    assert!(log[1].starts_with("end 5000 IdleTimeout"), "{log:?}");
    assert!(log[2].starts_with("start"), "{log:?}");
}

static LIVE_STATES: AtomicUsize = AtomicUsize::new(0);

/// Per-flow state that counts its live instances.
struct Counted;

impl Default for Counted {
    fn default() -> Self {
        LIVE_STATES.fetch_add(1, Ordering::SeqCst);
        Counted
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        LIVE_STATES.fetch_sub(1, Ordering::SeqCst);
    }
}

/// #162: `ctx.flow_state_mut` state is released when its flow ends
/// (it used to live for the monitor's lifetime).
#[tokio::test(flavor = "current_thread")]
async fn flow_state_is_released_when_its_flow_ends() {
    let file = pcap(&[udp(5000, 1), udp(6000, 200), udp(7000, 400)]);
    let max_live = Arc::new(AtomicUsize::new(0));
    let m = Arc::clone(&max_live);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        // The map's own idle timeout is long: only FlowEnded frees it.
        .flow_state::<Counted>(Duration::from_secs(3600))
        .on_ctx::<FlowStarted<Udp>>(
            move |_e: &FlowStarted<Udp>, ctx: &mut netring::ctx::Ctx<'_>| {
                ctx.flow_state_mut::<Counted>().expect("registered");
                m.fetch_max(LIVE_STATES.load(Ordering::SeqCst), Ordering::SeqCst);
                Ok(())
            },
        )
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(
        max_live.load(Ordering::SeqCst),
        1,
        "one flow alive at a time"
    );
    assert_eq!(LIVE_STATES.load(Ordering::SeqCst), 0, "all released");
}

/// #163: what a parser flushes when the connection closes (an
/// HTTP/1.0 response delimited by the close) reaches handlers before
/// the flow's `FlowEnded`.
#[tokio::test(flavor = "current_thread")]
async fn fin_flushed_message_precedes_flow_ended() {
    let (c, s, m) = ([10, 0, 0, 1], [10, 0, 0, 2], [0u8; 6]);
    let req = b"GET / HTTP/1.0\r\n\r\n";
    let resp = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nbody bytes";
    let (ci, si) = (100u32, 900u32);
    let frames = [
        ipv4_tcp(m, m, c, s, 40000, 80, ci, 0, 0x02, &[]),
        ipv4_tcp(m, m, s, c, 80, 40000, si, ci + 1, 0x12, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x10, &[]),
        ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x18, req),
        ipv4_tcp(
            m,
            m,
            s,
            c,
            80,
            40000,
            si + 1,
            ci + 1 + req.len() as u32,
            0x18,
            resp,
        ),
        // Server closes (the body ends here), client closes, last ACK.
        ipv4_tcp(
            m,
            m,
            s,
            c,
            80,
            40000,
            si + 1 + resp.len() as u32,
            ci + 1 + req.len() as u32,
            0x11,
            &[],
        ),
        ipv4_tcp(
            m,
            m,
            c,
            s,
            40000,
            80,
            ci + 1 + req.len() as u32,
            si + 2 + resp.len() as u32,
            0x11,
            &[],
        ),
        ipv4_tcp(
            m,
            m,
            s,
            c,
            80,
            40000,
            si + 2 + resp.len() as u32,
            ci + 2 + req.len() as u32,
            0x10,
            &[],
        ),
    ];
    let timed: Vec<_> = frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| (Duration::from_millis(1_000 + i as u64), f))
        .collect();
    let file = pcap(&timed);
    let log: Log = Arc::default();
    let (l1, l2) = (Arc::clone(&log), Arc::clone(&log));
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .protocol::<Http>()
        .on::<Http>(move |msg: &flowscope::http::HttpMessage| {
            let kind = match msg {
                flowscope::http::HttpMessage::Request(_) => "request",
                flowscope::http::HttpMessage::Response(_) => "response",
                _ => "other",
            };
            l1.lock().unwrap().push(kind.to_owned());
            Ok(())
        })
        .on::<FlowEnded<Tcp>>(move |e: &FlowEnded<Tcp>| {
            assert_eq!(e.reason, EndReason::Fin);
            l2.lock().unwrap().push("ended".to_owned());
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "request".to_owned(),
            "response".to_owned(),
            "ended".to_owned()
        ]
    );
}

struct FlushCounter(Arc<AtomicUsize>);

impl AnomalySink for FlushCounter {
    fn write(
        &mut self,
        _: &'static str,
        _: netring::Severity,
        _: flowscope::Timestamp,
        _: Option<&dyn netring::anomaly::Key>,
        _: &[(&'static str, std::borrow::Cow<'_, str>)],
        _: &[(&'static str, f64)],
    ) {
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// #169: the sink is flushed at exit even with no drain phase.
#[tokio::test(flavor = "current_thread")]
async fn sink_is_flushed_without_a_drain_phase() {
    let file = pcap(&[udp(5000, 1)]);
    let flushes = Arc::new(AtomicUsize::new(0));
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .drain_timeout(Duration::ZERO)
        .sink(FlushCounter(Arc::clone(&flushes)))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert!(flushes.load(Ordering::SeqCst) >= 1);
}

/// Tick handlers run on replay, on packet time (they never ran there):
/// one per period of capture time, stamped with the scheduled time, a
/// long silence costing one tick rather than a backlog.
#[tokio::test(flavor = "current_thread")]
async fn ticks_run_on_packet_time_during_replay() {
    // Packets at 1..=5 s, then one at 100 s.
    let mut frames: Vec<_> = (1..=5).map(|s| udp(5000, s)).collect();
    frames.push(udp(5000, 100));
    let file = pcap(&frames);
    let ticks = Arc::new(Mutex::new(Vec::new()));
    let t = Arc::clone(&ticks);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .tick_ctx(
            Duration::from_secs(1),
            move |ctx: &mut netring::ctx::Ctx<'_>| {
                t.lock().unwrap().push(ctx.ts.sec);
                Ok(())
            },
        )
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    // Armed at 1 s: due at 2, 3, 4, 5 (before the packets at those
    // times), then once for the 95 s gap.
    assert_eq!(*ticks.lock().unwrap(), vec![2, 3, 4, 5, 6]);
}
