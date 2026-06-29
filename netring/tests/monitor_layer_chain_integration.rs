//! 0.21 D.3: full layer-chain integration test.
//!
//! Drives synthetic anomalies through the prelude-imported layer
//! stack and asserts exact pass-through counts. Doesn't open
//! AF_PACKET — feeds a [`ChannelSink`] from a layered sink chain
//! by invoking `AnomalyWriter::emit` directly. Each layer's
//! drop behavior is observable from the count delta between the
//! emit site and the channel's receive side.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flowscope::Timestamp;
use netring::anomaly::Severity;
use netring::anomaly::shipped_sinks::ChannelSink;
use netring::anomaly::sink::AnomalySink;
use netring::layer::{DedupeAnomalies, Layer, MinSeverity, RateLimitAnomalies};

fn key() -> flowscope::extract::FiveTupleKey {
    flowscope::extract::FiveTupleKey::new(
        flowscope::L4Proto::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    )
}

/// Build the chain `outer.wrap(... inner.wrap(base))`. Matches
/// the `MonitorBuilder::build()` ordering: layers in registration
/// order, applied innermost-first so the first registered layer
/// ends up outermost.
fn layer_chain(base: Box<dyn AnomalySink>, layers: Vec<Box<dyn Layer>>) -> Box<dyn AnomalySink> {
    let mut sink = base;
    for layer in layers.into_iter().rev() {
        sink = layer.wrap(sink);
    }
    sink
}

#[tokio::test]
async fn min_severity_drops_info_emissions() {
    let (channel_sink, mut rx) = ChannelSink::channel();
    let base: Box<dyn AnomalySink> = Box::new(channel_sink);
    let mut sink = layer_chain(base, vec![Box::new(MinSeverity::warning())]);

    let k = key();
    for _ in 0..100 {
        sink.begin("InfoKind", Severity::Info, Timestamp::new(0, 0))
            .with_key(&k)
            .emit();
        sink.begin("WarnKind", Severity::Warning, Timestamp::new(0, 0))
            .with_key(&k)
            .emit();
    }

    // MinSeverity::warning() drops every Info; every Warning passes.
    let mut received = 0;
    while rx.try_recv().is_ok() {
        received += 1;
    }
    assert_eq!(received, 100, "expected 100 Warning emissions to survive");
}

#[tokio::test]
async fn dedupe_same_kind_same_key_within_window() {
    let (channel_sink, mut rx) = ChannelSink::channel();
    let base: Box<dyn AnomalySink> = Box::new(channel_sink);
    let mut sink = layer_chain(
        base,
        vec![Box::new(DedupeAnomalies::within(Duration::from_secs(60)))],
    );

    let k = key();
    // Same (kind, key) repeated 50 times within the 60s window —
    // exactly one should reach the channel.
    for _ in 0..50 {
        sink.begin("Repeat", Severity::Warning, Timestamp::new(0, 0))
            .with_key(&k)
            .emit();
    }

    let mut received = 0;
    while rx.try_recv().is_ok() {
        received += 1;
    }
    assert_eq!(received, 1, "DedupeAnomalies should fold 50 → 1");
}

#[tokio::test]
async fn dedupe_distinct_kinds_pass_through() {
    let (channel_sink, mut rx) = ChannelSink::channel();
    let base: Box<dyn AnomalySink> = Box::new(channel_sink);
    let mut sink = layer_chain(
        base,
        vec![Box::new(DedupeAnomalies::within(Duration::from_secs(60)))],
    );

    let k = key();
    // Distinct kinds: dedupe key differs → all 10 pass.
    for i in 0..10 {
        // Static-str kind per `AnomalyWriter::begin` signature.
        let kind: &'static str = match i {
            0 => "K0",
            1 => "K1",
            2 => "K2",
            3 => "K3",
            4 => "K4",
            5 => "K5",
            6 => "K6",
            7 => "K7",
            8 => "K8",
            _ => "K9",
        };
        sink.begin(kind, Severity::Warning, Timestamp::new(0, 0))
            .with_key(&k)
            .emit();
    }

    let mut received = 0;
    while rx.try_recv().is_ok() {
        received += 1;
    }
    assert_eq!(received, 10);
}

#[tokio::test]
async fn full_chain_min_severity_then_dedupe_then_ratelimit() {
    let (channel_sink, mut rx) = ChannelSink::channel();
    let base: Box<dyn AnomalySink> = Box::new(channel_sink);
    // Registration order: MinSeverity outermost, then Dedupe,
    // then RateLimit. Matches the order `MonitorBuilder::layer()`
    // documents: the first registered layer is outermost.
    let mut sink = layer_chain(
        base,
        vec![
            Box::new(MinSeverity::warning()),
            Box::new(DedupeAnomalies::within(Duration::from_secs(60))),
            Box::new(RateLimitAnomalies::new(100, Duration::from_secs(1))),
        ],
    );

    let k = key();
    // 100 Info (dropped by MinSeverity) + 50 distinct kinds at
    // Warning (each unique → Dedupe passes all) + 100 same-kind
    // Warning (Dedupe folds to 1 → RateLimit lets it through).
    for _ in 0..100 {
        sink.begin("InfoSpam", Severity::Info, Timestamp::new(0, 0))
            .with_key(&k)
            .emit();
    }
    for i in 0..50 {
        let kind: &'static str = match i {
            0 => "D00",
            1 => "D01",
            2 => "D02",
            3 => "D03",
            4 => "D04",
            5 => "D05",
            6 => "D06",
            7 => "D07",
            8 => "D08",
            9 => "D09",
            10 => "D10",
            11 => "D11",
            12 => "D12",
            13 => "D13",
            14 => "D14",
            15 => "D15",
            16 => "D16",
            17 => "D17",
            18 => "D18",
            19 => "D19",
            20 => "D20",
            21 => "D21",
            22 => "D22",
            23 => "D23",
            24 => "D24",
            25 => "D25",
            26 => "D26",
            27 => "D27",
            28 => "D28",
            29 => "D29",
            30 => "D30",
            31 => "D31",
            32 => "D32",
            33 => "D33",
            34 => "D34",
            35 => "D35",
            36 => "D36",
            37 => "D37",
            38 => "D38",
            39 => "D39",
            40 => "D40",
            41 => "D41",
            42 => "D42",
            43 => "D43",
            44 => "D44",
            45 => "D45",
            46 => "D46",
            47 => "D47",
            48 => "D48",
            _ => "D49",
        };
        sink.begin(kind, Severity::Warning, Timestamp::new(0, 0))
            .with_key(&k)
            .emit();
    }
    for _ in 0..100 {
        sink.begin("Repeat", Severity::Warning, Timestamp::new(0, 0))
            .with_key(&k)
            .emit();
    }

    let mut received = 0;
    while rx.try_recv().is_ok() {
        received += 1;
    }
    // 0 (Info dropped) + 50 (distinct kinds) + 1 (deduped repeats) = 51.
    // RateLimit with 100/sec budget doesn't trim anything at this volume.
    assert_eq!(
        received, 51,
        "expected 0 Info + 50 distinct Warning + 1 deduped Warning = 51"
    );
}
