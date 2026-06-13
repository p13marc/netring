//! 0.22 §2.3 — bandwidth-by-app primitive.
//!
//! A per-app rolling byte-rate keyed by the flow's well-known app
//! label (`"http"`, `"https"`, `"dns"`, site-custom labels via a
//! [`LabelTable`](flowscope::well_known::LabelTable)). The recorder
//! is a single internal `on_ctx::<FlowPacket>` handler that feeds
//! `evt.len` into a hidden [`RollingRate<&'static str, u64>`] slot —
//! zero-alloc on the per-packet path (bucket/key reuse).
//!
//! Three API layers, each a thin wrapper over the next:
//! 1. [`MonitorBuilder::bandwidth_by_app`](crate::monitor::MonitorBuilder::bandwidth_by_app)
//!    — register the primitive.
//! 2. [`BandwidthReport`] — a strongly-typed read view (`top`,
//!    `rate`, `total`); no `RollingRate` / `Timestamp` / `Option`
//!    leakage.
//! 3. [`MonitorBuilder::on_bandwidth`](crate::monitor::MonitorBuilder::on_bandwidth)
//!    — fused one-liner: auto-register + periodic report.

use std::time::Duration;

use crate::correlate::RollingRate;

/// Default rolling window: 10s of bytes in 1s buckets → a bytes/sec
/// rate with ~1s resolution.
pub(crate) const BW_WINDOW: Duration = Duration::from_secs(10);
pub(crate) const BW_BUCKET: Duration = Duration::from_secs(1);

/// Private newtype wrapping the bandwidth slot's [`RollingRate`] so
/// its `TypeId` is netring-owned and can't collide with a user-
/// registered `RollingRate<&'static str, u64>` state slot.
pub(crate) struct BandwidthState(pub(crate) RollingRate<&'static str, u64>);

impl BandwidthState {
    pub(crate) fn new(window: Duration, bucket: Duration) -> Self {
        Self(RollingRate::new_unbounded(window, bucket))
    }
}

impl Default for BandwidthState {
    /// Satisfies the `Default` bound on `Ctx::state_mut` only. The
    /// real slot is always pre-inserted by `bandwidth_windowed` via
    /// `state_init`, so this default (matching the standard 10s/1s
    /// window) is never actually constructed in practice.
    fn default() -> Self {
        Self::new(BW_WINDOW, BW_BUCKET)
    }
}

/// 0.22 §2.3: a strongly-typed read view over the bandwidth slot at a
/// fixed instant. Obtained from
/// [`Ctx::bandwidth`](crate::ctx::Ctx::bandwidth) or a report
/// snapshot; the `Timestamp` is captured internally so callers never
/// handle one.
pub struct BandwidthReport<'a> {
    pub(crate) rate: &'a RollingRate<&'static str, u64>,
    pub(crate) now: flowscope::Timestamp,
}

impl BandwidthReport<'_> {
    /// Top-`n` apps by bytes/sec, descending.
    pub fn top(&self, n: usize) -> Vec<(&'static str, f64)> {
        self.rate.top_k(n, self.now)
    }

    /// Bytes/sec for one app label (`0.0` if unseen in the window).
    /// Pass a `&'static str` (a string literal or a label from
    /// [`FiveTupleKey::app_label`](flowscope::extract::FiveTupleKey::app_label)).
    pub fn rate(&self, app: &'static str) -> f64 {
        self.rate.rate(&app, self.now)
    }

    /// Total bytes/sec across every app in the window.
    pub fn total(&self) -> f64 {
        self.rate.snapshot(self.now).map(|(_, r)| r).sum()
    }

    /// Number of distinct in-window apps.
    pub fn app_count(&self) -> usize {
        self.rate.len(self.now)
    }

    /// 0.22 §3: owned top-`n` snapshot for a
    /// [`ReportSink`](crate::report::ReportSink). Implements
    /// [`Report`](crate::report::Report) (+ `Serialize` under `serde`),
    /// so it ships through `report_to(..)`.
    pub fn to_snapshot(&self, n: usize) -> BandwidthSnapshot {
        BandwidthSnapshot {
            apps: self
                .top(n)
                .into_iter()
                .map(|(app, bytes_per_sec)| BandwidthEntry { app, bytes_per_sec })
                .collect(),
        }
    }
}

/// One app's bytes/sec in a [`BandwidthSnapshot`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BandwidthEntry {
    /// App label (`"http"`, site-custom, …).
    pub app: &'static str,
    /// Bytes per second over the rolling window.
    pub bytes_per_sec: f64,
}

/// 0.22 §3: an owned, top-N bandwidth snapshot — the reference
/// [`Report`](crate::report::Report). `report_to(period, |snap|
/// snap.bandwidth().unwrap().to_snapshot(10), JsonReportSink)` ships it
/// as newline-JSON.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BandwidthSnapshot {
    /// Top apps by bytes/sec, descending.
    pub apps: Vec<BandwidthEntry>,
}

impl crate::report::Report for BandwidthSnapshot {
    const NAME: &'static str = "bandwidth";
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use flowscope::{FlowSide, L4Proto, Timestamp};

    use super::*;
    use crate::ctx::{Ctx, SourceIdx};
    use crate::monitor::Monitor;
    use crate::protocol::event_typed::FlowPacket;

    fn key(proto: L4Proto, dport: u16) -> flowscope::extract::FiveTupleKey {
        flowscope::extract::FiveTupleKey {
            proto,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 40000),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), dport),
        }
    }

    #[test]
    fn report_view_top_rate_total() {
        // Hand-built RollingRate: 300 B http, 100 B dns over a 10s window.
        let now = Timestamp::new(1_000, 0);
        let mut rate = RollingRate::<&'static str, u64>::new_unbounded(BW_WINDOW, BW_BUCKET);
        rate.record("http", 300, now);
        rate.record("dns", 100, now);
        let report = BandwidthReport { rate: &rate, now };

        assert_eq!(report.top(10).first().map(|(a, _)| *a), Some("http"));
        assert_eq!(report.app_count(), 2);
        assert!((report.rate("http") - 30.0).abs() < 1e-6); // 300 / 10s
        assert!((report.rate("dns") - 10.0).abs() < 1e-6);
        assert!((report.total() - 40.0).abs() < 1e-6);
        assert_eq!(report.rate("ssh"), 0.0); // unseen → 0
    }

    #[test]
    fn builder_recorder_buckets_by_app_then_ctx_reads_back() {
        // End-to-end through the builder: the internal recorder feeds
        // the slot; `ctx.bandwidth()` reads it. Same-crate access to
        // the pub(crate) Monitor fields lets us drive the dispatcher
        // without a live capture.
        let monitor = Monitor::builder()
            .interface("lo")
            .bandwidth_by_app()
            .build()
            .expect("build");
        let Monitor {
            mut dispatcher,
            mut state_map,
            mut counters,
            mut flow_states,
            mut sink,
            ..
        } = monitor;

        let now = Timestamp::new(2_000, 0);
        let mut feed = |proto: L4Proto, dport: u16, len: usize| {
            let mut ctx = Ctx::new(
                None,
                now,
                SourceIdx(0),
                &mut state_map,
                sink.as_mut(),
                &mut counters,
                &mut flow_states,
            );
            let pkt = FlowPacket::new(
                proto,
                key(proto, dport),
                FlowSide::Initiator,
                len,
                None,
                now,
            );
            dispatcher.dispatch::<FlowPacket>(&pkt, &mut ctx).unwrap();
        };
        for _ in 0..3 {
            feed(L4Proto::Tcp, 80, 100); // http
        }
        for _ in 0..2 {
            feed(L4Proto::Udp, 53, 50); // dns
        }

        let ctx = Ctx::new(
            None,
            now,
            SourceIdx(0),
            &mut state_map,
            sink.as_mut(),
            &mut counters,
            &mut flow_states,
        );
        let report = ctx.bandwidth().expect("bandwidth registered");
        assert_eq!(report.top(10).first().map(|(a, _)| *a), Some("http"));
        assert!((report.rate("http") - 30.0).abs() < 1e-6); // 300/10s
        assert!((report.rate("dns") - 10.0).abs() < 1e-6); // 100/10s
        assert_eq!(report.app_count(), 2);
    }
}
