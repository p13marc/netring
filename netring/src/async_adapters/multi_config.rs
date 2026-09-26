//! [`MultiStreamConfig`] — per-source config applied uniformly at
//! `Multi*Stream` construction.
//!
//! Plan 26: post-hoc `with_*` chaining on a `Multi*Stream` doesn't
//! reach the per-source `FlowStream`s through `SelectState`'s
//! boxed fan-in without leaking internal types. Instead, config
//! goes in at construction via the
//! `AsyncMultiCapture::*_stream_with(extractor, …, config)` family.
//!
//! Each per-source inner stream gets a clone of the config's
//! `tracker_config`, an Arc'd `idle_timeout_fn` if set, a freshly
//! cloned `dedup` template (cloning resets counters — see
//! `Dedup::clone`), and the `monotonic_ts` toggle.

use std::sync::Arc;
use std::time::Duration;

use flowscope::{FlowExtractor, FlowTrackerConfig, L4Proto};

use crate::async_adapters::flow_stream::FlowStream;
use crate::dedup::Dedup;

/// Closure type for per-key idle-timeout overrides. Shared across
/// per-source streams via `Arc` so the closure can be cloned cheaply.
pub type SharedIdleTimeoutFn<K> =
    Arc<dyn Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static>;

/// Per-source config applied uniformly to every inner stream of a
/// [`MultiFlowStream`] / [`MultiSessionStream`] /
/// [`MultiDatagramStream`].
///
/// Construct via [`MultiStreamConfig::new`] (returns default) plus
/// the `with_*` builder methods. Pass to
/// [`AsyncMultiCapture::flow_stream_with`] /
/// [`session_stream_with`] / [`datagram_stream_with`].
///
/// # Per-knob semantics
///
/// - `tracker_config`: cloned per source — each source's
///   `FlowTracker` gets its own copy.
/// - `dedup`: cloned per source. **Note**: [`Dedup`] clones reset
///   their ring + counters, so each source has independent dedup
///   state.
/// - `idle_timeout_fn`: shared via `Arc`; the same closure is
///   invoked from every source.
/// - `monotonic_ts`: a bool — when `true`, monotonic-timestamp
///   clamping is enabled on every inner stream.
/// - `emit_anomalies`: session / datagram streams also yield
///   `FlowAnomaly` / `TrackerAnomaly` events (gaps, overflow, memcap,
///   eviction pressure). Flow streams reassemble nothing and ignore it.
///
/// [`AsyncMultiCapture::flow_stream_with`]: super::multi_capture::AsyncMultiCapture::flow_stream_with
/// [`session_stream_with`]: super::multi_capture::AsyncMultiCapture::session_stream_with
/// [`datagram_stream_with`]: super::multi_capture::AsyncMultiCapture::datagram_stream_with
/// [`MultiFlowStream`]: super::multi_streams::MultiFlowStream
/// [`MultiSessionStream`]: super::multi_streams::MultiSessionStream
/// [`MultiDatagramStream`]: super::multi_streams::MultiDatagramStream
pub struct MultiStreamConfig<K> {
    /// Tracker config applied to each inner per-source tracker.
    pub tracker_config: FlowTrackerConfig,
    /// Optional dedup template, cloned per source.
    pub dedup: Option<Dedup>,
    /// Optional per-key idle-timeout predicate, shared per-source.
    pub idle_timeout_fn: Option<SharedIdleTimeoutFn<K>>,
    /// Apply monotonic-timestamp clamping to each inner stream.
    pub monotonic_ts: bool,
    /// Session / datagram streams yield anomaly events.
    pub emit_anomalies: bool,
}

impl<K> Default for MultiStreamConfig<K> {
    fn default() -> Self {
        Self {
            tracker_config: FlowTrackerConfig::default(),
            dedup: None,
            idle_timeout_fn: None,
            monotonic_ts: false,
            emit_anomalies: false,
        }
    }
}

impl<K> Clone for MultiStreamConfig<K> {
    fn clone(&self) -> Self {
        Self {
            tracker_config: self.tracker_config.clone(),
            dedup: self.dedup.clone(),
            idle_timeout_fn: self.idle_timeout_fn.clone(),
            monotonic_ts: self.monotonic_ts,
            emit_anomalies: self.emit_anomalies,
        }
    }
}

impl<K> std::fmt::Debug for MultiStreamConfig<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiStreamConfig")
            .field("tracker_config", &self.tracker_config)
            .field("has_dedup", &self.dedup.is_some())
            .field("has_idle_timeout_fn", &self.idle_timeout_fn.is_some())
            .field("monotonic_ts", &self.monotonic_ts)
            .field("emit_anomalies", &self.emit_anomalies)
            .finish()
    }
}

impl<K> MultiStreamConfig<K> {
    /// Empty config — all knobs at defaults. Equivalent to
    /// [`Default::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the per-source [`FlowTrackerConfig`].
    pub fn with_tracker_config(mut self, c: FlowTrackerConfig) -> Self {
        self.tracker_config = c;
        self
    }

    /// Enable SYN-based TCP initiator inference on every per-source
    /// tracker (flowscope 0.20 #122). When on, a flow whose first
    /// observed packet is a `SYN+ACK` — the response delivered before
    /// the request, the classic tap-merge / two-queue race — has its
    /// inferred initiator flipped so the SYN sender is labelled
    /// `Initiator`, and `FlowStats::direction_flipped` is set.
    /// Recommended for tap-merge / multi-queue fan-in; a no-op for a
    /// single tap (where the SYN is always seen first). Default off.
    pub fn with_infer_tcp_initiator(mut self, enable: bool) -> Self {
        self.tracker_config.infer_tcp_initiator = enable;
        self
    }

    /// Provide a [`Dedup`] template to be cloned per source.
    pub fn with_dedup(mut self, d: Dedup) -> Self {
        self.dedup = Some(d);
        self
    }

    /// Set a per-key idle-timeout predicate applied uniformly to
    /// every per-source inner stream.
    pub fn with_idle_timeout_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.idle_timeout_fn = Some(Arc::new(f));
        self
    }

    /// Toggle monotonic-timestamp clamping for every inner stream.
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = enable;
        self
    }

    /// Session / datagram streams also yield `FlowAnomaly` /
    /// `TrackerAnomaly` events. Default off.
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }

    /// Apply the flow-level knobs (tracker config, dedup, idle-timeout
    /// predicate, clamp) to one source's stream.
    pub(crate) fn apply<C, E>(&self, stream: FlowStream<C, E>) -> FlowStream<C, E>
    where
        E: FlowExtractor<Key = K>,
        K: 'static,
    {
        let mut s = stream.with_config(self.tracker_config.clone());
        if let Some(d) = &self.dedup {
            s = s.with_dedup(d.clone());
        }
        if let Some(f) = &self.idle_timeout_fn {
            let f = f.clone();
            s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
        }
        if self.monotonic_ts {
            s = s.with_monotonic_timestamps(true);
        }
        s
    }
}
