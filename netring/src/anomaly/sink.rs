//! Anomaly sink — destination for anomaly emissions from the 0.20
//! [`Monitor`](crate::monitor::Monitor) handler pipeline.
//!
//! Handlers do **not** construct an [`Anomaly`](crate::anomaly::Anomaly)
//! value. They invoke [`AnomalySinkExt::begin`] which returns an
//! [`AnomalyWriter`] — a stack-only builder that writes directly
//! into a sink-owned buffer. The framework never materialises an
//! `Anomaly<K>` on the hot path, so the steady-state allocation
//! budget is whatever the sink itself decides to allocate.
//!
//! ```ignore
//! ctx.sink_mut()
//!     .begin("FlowStartedTcp", Severity::Info, ctx.ts)
//!     .with_key(flow_key)
//!     .with("note", "first packet")
//!     .with_metric("bytes", 64.0)
//!     .emit();
//! ```
//!
//! ## Allocation envelope
//!
//! - [`AnomalyWriter`] uses
//!   `ArrayVec<(&'static str, Cow<'_, str>), 8>` for observations
//!   and `ArrayVec<(&'static str, f64), 8>` for metrics. Both fit
//!   inline; a 9th entry is silently dropped (documented; switch
//!   to a custom sink if you need more).
//! - `&'static str` values pass through `with(...)` with zero
//!   allocations. `String` values cost one allocation per emit.
//! - The sink callback ([`AnomalySink::write`]) receives one borrowed
//!   [`AnomalyRecord`]; sinks that need to retain the anomaly (e.g.
//!   `ChannelSink`) are responsible for the copy
//!   ([`AnomalyRecord::to_owned_anomaly`]).
//!
//! ## Endpoints (0.32)
//!
//! A flow key is address-sorted (`key.a < key.b`), so its `a` is not
//! the endpoint that opened the connection. [`AnomalyWriter::emit`]
//! resolves the anomaly's [`Endpoints`] — `src` / `dest` as sinks render
//! them — from the flow's **initiator** whenever it knows it: the key is
//! the flow [`Ctx::emit`](crate::ctx::Ctx::emit) was called for, or the
//! handler said which side opened it ([`AnomalyWriter::with_flow`] /
//! [`AnomalyWriter::with_initiator`]). Otherwise the key is read as
//! stored, `a` → `b`, and [`Endpoints::directional`] is `false`.
//!
//! ## Phase B → Phase C
//!
//! Phase B shipped an empty trait stub. Phase C fills in the real
//! API. The `NoopSink` default still works without changes —
//! `write` has no default and `NoopSink` overrides with an empty
//! body.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};

use arrayvec::ArrayVec;
use flowscope::extract::FiveTupleKey;
use flowscope::{KeyFields, Orientation, Timestamp};

use crate::anomaly::Severity;
use crate::anomaly::key::Key;

/// Maximum observations / metrics inline per [`AnomalyWriter`].
/// Values beyond this are silently dropped; the [`AnomalyWriter`]
/// docs surface the limit.
pub const ANOMALY_INLINE_CAPACITY: usize = 8;

/// The endpoints an anomaly is about, as sinks render them: `src_*` /
/// `dest_*` plus the L4 protocol label.
///
/// When [`Self::directional`] is `true`, `src` is the flow's
/// **initiator** — or, for an anomaly about one endpoint, its subject —
/// and `dest` the other side. When it is `false` the endpoints are a flow
/// key read as stored (`key.a` → `key.b`, the address-sorted order), which
/// says nothing about who opened the connection.
///
/// [`AnomalyWriter::emit`] fills it from the attached key; a sink reads it
/// off [`AnomalyRecord::endpoints`]. New in 0.32.0 (#215).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoints {
    /// Source address — the initiator when [`Self::directional`].
    pub src_ip: Option<IpAddr>,
    /// Source port, when the protocol has ports.
    pub src_port: Option<u16>,
    /// Destination address — the responder when [`Self::directional`].
    pub dest_ip: Option<IpAddr>,
    /// Destination port, when the protocol has ports.
    pub dest_port: Option<u16>,
    /// L4 protocol label (`"TCP"`, `"UDP"`, `"ICMP"`, `"ICMPv6"`,
    /// `"SCTP"`), as [`flowscope::KeyFields::proto_str`] spells it.
    pub proto: Option<&'static str>,
    /// `true`: `src` is the flow's initiator (or the anomaly's subject);
    /// `false`: the canonical `a` → `b` order of an address-sorted key.
    pub directional: bool,
}

impl Endpoints {
    /// `src` → `dest` over `proto`; `directional` says whether `src` is
    /// the initiator / the subject (see [`Self::directional`]).
    pub fn new(
        src: SocketAddr,
        dest: SocketAddr,
        proto: Option<&'static str>,
        directional: bool,
    ) -> Self {
        Self {
            src_ip: Some(src.ip()),
            src_port: Some(src.port()),
            dest_ip: Some(dest.ip()),
            dest_port: Some(dest.port()),
            proto,
            directional,
        }
    }

    /// A flow read from its initiator: `initiator` is the orientation of
    /// the endpoint that opened it (`Forward`: `key.a`; see
    /// [`flowscope::FlowStats::initiator_orientation`] and
    /// [`Ctx::initiator`](crate::ctx::Ctx::initiator)). Directional.
    pub fn from_flow(key: &FiveTupleKey, initiator: Orientation) -> Self {
        let (src, dest) = key.oriented(initiator);
        Self::new(src, dest, key.proto_str(), true)
    }

    /// A flow key read as stored, `a` → `b`. Not directional.
    pub fn canonical(key: &FiveTupleKey) -> Self {
        Self::new(key.a, key.b, key.proto_str(), false)
    }

    /// The 5-tuple fields of an owned anomaly, which flowscope's
    /// detectors and [`flowscope::OwnedAnomaly::with_flow`] fill from the
    /// initiator (directional). `None` when it carries no address.
    pub fn from_owned(anomaly: &flowscope::OwnedAnomaly) -> Option<Self> {
        if anomaly.src_ip.is_none() && anomaly.dest_ip.is_none() {
            return None;
        }
        Some(Self {
            src_ip: anomaly.src_ip,
            src_port: anomaly.src_port,
            dest_ip: anomaly.dest_ip,
            dest_port: anomaly.dest_port,
            proto: anomaly.proto,
            directional: true,
        })
    }

    /// `src` as a socket address (both the address and the port known).
    pub fn src(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.src_ip?, self.src_port?))
    }

    /// `dest` as a socket address (both the address and the port known).
    pub fn dest(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.dest_ip?, self.dest_port?))
    }
}

/// One anomaly, as an [`AnomalySink`] receives it: borrowed, built by
/// [`AnomalyWriter::emit`] on the stack (no allocation).
///
/// Sinks render `src` / `dest` from [`Self::endpoints`] — resolved from
/// the flow's initiator when the emitter knew it — and may still read the
/// raw [`Self::key`] (its `Debug` text, or [`Self::flow_key`]) for the
/// flow's identity. New in 0.32.0 (#215); it replaces `write`'s six
/// positional arguments.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct AnomalyRecord<'a> {
    /// The detector / rule slug.
    pub kind: &'static str,
    /// Severity tier.
    pub severity: Severity,
    /// Event timestamp (packet time).
    pub ts: Timestamp,
    /// The key the emitter attached — typically a flow key
    /// ([`FiveTupleKey`], address-sorted) or a host (`IpAddr`).
    pub key: Option<&'a dyn Key>,
    /// Who the anomaly is about, `src` → `dest` (see [`Endpoints`]).
    /// `None` when the emitter attached no flow key and no endpoints.
    pub endpoints: Option<Endpoints>,
    /// Free-form `(label, value)` observations.
    pub observations: &'a [(&'static str, Cow<'a, str>)],
    /// `(label, value)` numeric metrics.
    pub metrics: &'a [(&'static str, f64)],
}

impl<'a> AnomalyRecord<'a> {
    /// A record with no key, endpoints, observations or metrics — for
    /// sinks' tests and hand-built records; handlers emit through
    /// [`AnomalyWriter`].
    pub fn new(kind: &'static str, severity: Severity, ts: Timestamp) -> Self {
        Self {
            kind,
            severity,
            ts,
            key: None,
            endpoints: None,
            observations: &[],
            metrics: &[],
        }
    }

    /// Attach a key. A [`FiveTupleKey`] also sets the endpoints, read as
    /// stored ([`Endpoints::canonical`]), unless they are already set.
    pub fn with_key(mut self, key: &'a dyn Key) -> Self {
        self.key = Some(key);
        if self.endpoints.is_none() {
            self.endpoints = self.flow_key().map(Endpoints::canonical);
        }
        self
    }

    /// Set the endpoints.
    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// Set the observations.
    pub fn with_observations(mut self, observations: &'a [(&'static str, Cow<'a, str>)]) -> Self {
        self.observations = observations;
        self
    }

    /// Set the metrics.
    pub fn with_metrics(mut self, metrics: &'a [(&'static str, f64)]) -> Self {
        self.metrics = metrics;
        self
    }

    /// The key as a flow key, when it is one.
    pub fn flow_key(&self) -> Option<&'a FiveTupleKey> {
        self.key?.as_any().downcast_ref::<FiveTupleKey>()
    }

    /// An owned copy, for sinks that retain the anomaly: the 5-tuple
    /// fields come from [`Self::endpoints`] (so `src_*` is the initiator
    /// when they are directional), the observations are copied.
    pub fn to_owned_anomaly(&self) -> flowscope::OwnedAnomaly {
        let mut owned = flowscope::OwnedAnomaly::new(
            detector_kind_for(self.kind),
            self.severity.into(),
            self.ts,
        );
        if let Some(e) = self.endpoints {
            owned.src_ip = e.src_ip;
            owned.src_port = e.src_port;
            owned.dest_ip = e.dest_ip;
            owned.dest_port = e.dest_port;
            owned.proto = e.proto;
        }
        for (label, value) in self.observations {
            owned = owned.with_observation(label, value.clone().into_owned());
        }
        for (label, value) in self.metrics {
            owned = owned.with_metric(label, *value);
        }
        owned
    }
}

/// Destination for anomalies emitted by the 0.20 [`crate::monitor::Monitor`].
///
/// Implementations are usually small structs with a reusable
/// scratch buffer; the trait is **object-safe** so handlers can
/// receive `&mut dyn AnomalySink` without monomorphising per
/// sink type.
///
/// `begin(...)` (the writer-starting method) is provided in two
/// places to satisfy both monomorphic and trait-object call
/// sites:
/// - `impl dyn AnomalySink + '_` (below) for `&mut dyn AnomalySink`
/// - blanket [`AnomalySinkExt`] for any `T: AnomalySink + Sized`
pub trait AnomalySink: Send {
    /// Render the anomaly. Called by [`AnomalyWriter::emit`]; sinks
    /// own this — that's the one method every impl provides.
    ///
    /// The record is borrowed for the call. Render `src` / `dest` from
    /// [`AnomalyRecord::endpoints`] (initiator first when
    /// [`Endpoints::directional`]); the raw key stays available as
    /// [`AnomalyRecord::key`] (`Debug` text) and
    /// [`AnomalyRecord::flow_key`]. 0.32 (#215): one record replaces the
    /// six positional arguments.
    fn write(&mut self, record: &AnomalyRecord<'_>);

    /// Optional shutdown hook. Default is a no-op.
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// `begin(...)` on `&mut dyn AnomalySink` — used by layered sink
/// chains and any code that holds a trait object.
impl dyn AnomalySink + '_ {
    /// Construct an [`AnomalyWriter`] anchored on this trait object.
    pub fn begin(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> AnomalyWriter<'_> {
        AnomalyWriter::new(self, kind, severity, ts)
    }
}

/// Convenience extension — lets typed sinks call `.begin(...)`
/// directly without coercing through `&mut dyn AnomalySink`.
pub trait AnomalySinkExt: AnomalySink + Sized {
    /// Construct an [`AnomalyWriter`] anchored on this sink.
    fn begin(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> AnomalyWriter<'_> {
        AnomalyWriter::new(self, kind, severity, ts)
    }
}

impl<T: AnomalySink + Sized> AnomalySinkExt for T {}

/// 0.21 I.1: publish a `flowscope::OwnedAnomaly` through any
/// [`AnomalySink`] (including layered chains via
/// `dyn AnomalySink`). Used by the `pattern_detector!` macro to
/// route detector-emitted [`flowscope::DetectorScore::into_anomaly`]
/// outputs into the sink chain.
///
/// Constraints:
/// - `OwnedAnomaly::kind` is a typed `flowscope::DetectorKind` (flowscope
///   0.22); `as_str()` yields the `&'static str` slug `AnomalySink::write`
///   wants for every variant, so no `Box::leak` is ever needed.
/// - Observations and metrics are forwarded as borrowed slices —
///   no copy beyond the `Cow::Borrowed` re-wrap.
/// - The record carries no `key`; the anomaly's 5-tuple fields become
///   its [`Endpoints`] ([`Endpoints::from_owned`], directional — flowscope
///   fills them from the flow's initiator, or the anomaly's subject).
pub fn publish_owned(sink: &mut dyn AnomalySink, owned: &flowscope::OwnedAnomaly) {
    // Translate the SmallVec<Cow<'static, str>> observations into the
    // borrowed slice shape AnomalySink::write expects. The internal
    // Cow stays borrowed so no clone happens here.
    let mut observations: Vec<(&'static str, std::borrow::Cow<'_, str>)> = owned
        .observations
        .iter()
        .map(|(k, v)| (*k, std::borrow::Cow::Borrowed(v.as_ref())))
        .collect();
    // Issue #127: surface the MITRE ATT&CK technique for detector-kinded
    // anomalies as an observation, so it reaches every sink (JSON / EVE / OCSF).
    if let Some(tid) = owned.kind.attack_technique() {
        observations.push(("attack_technique", std::borrow::Cow::Borrowed(tid)));
    }
    let metrics: Vec<(&'static str, f64)> = owned.metrics.iter().copied().collect();
    // flowscope 0.22: `OwnedAnomaly::kind` is a typed `DetectorKind` whose
    // `as_str()` yields a `&'static str` slug for every variant (including
    // `Other`) — no more `Cow`/`Box::leak` dance.
    let kind: &'static str = owned.kind.as_str();
    let mut record = AnomalyRecord::new(kind, owned.severity.into(), owned.ts)
        .with_observations(&observations)
        .with_metrics(&metrics);
    record.endpoints = Endpoints::from_owned(owned);
    sink.write(&record);
}

/// `ip:port` (`[ip]:port` for IPv6), the bare address without a port,
/// `-` without an address — how the text sinks print an endpoint.
pub(crate) fn endpoint_text(ip: Option<IpAddr>, port: Option<u16>) -> impl std::fmt::Display {
    struct Text(Option<IpAddr>, Option<u16>);
    impl std::fmt::Display for Text {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match (self.0, self.1) {
                (Some(ip), Some(port)) => SocketAddr::new(ip, port).fmt(f),
                (Some(ip), None) => ip.fmt(f),
                (None, _) => f.write_str("-"),
            }
        }
    }
    Text(ip, port)
}

/// Map a netring anomaly `kind` slug back to a flowscope [`DetectorKind`]
/// (issue #132 / #127). Used when building a `flowscope::OwnedAnomaly` from
/// netring-side writer state (EVE / channel / owned sinks).
///
/// Round-trips through [`DetectorKind::from_slug`]: if the slug is a known
/// built-in it recovers the typed variant (so `attack_technique()` works), and
/// if not it becomes `Other(slug)` — never `Unknown`, which would silently
/// rewrite the emitted slug to `"unknown"`.
pub(crate) fn detector_kind_for(kind: &'static str) -> flowscope::DetectorKind {
    let parsed = flowscope::DetectorKind::from_slug(kind);
    if parsed.as_str() == kind {
        parsed
    } else {
        flowscope::DetectorKind::Other(kind)
    }
}

/// Stack-only builder for a single anomaly. Each `with_*` method
/// returns the writer by value; finalize with [`Self::emit`].
///
/// Storage is `ArrayVec` so the writer fits inside a single
/// stack frame. Overflow drops the offending entry silently.
///
/// The [`Endpoints`] the sink receives are resolved at [`Self::emit`]
/// (first match wins):
///
/// 1. set with [`Self::with_endpoints`];
/// 2. the attached flow key read from the initiator given by
///    [`Self::with_flow`] / [`Self::with_initiator`];
/// 3. the attached flow key read from its initiator when it is the flow
///    [`Ctx::emit`](crate::ctx::Ctx::emit) was called for (either way
///    round) and the dispatch knows who opened it;
/// 4. the attached flow key read as stored, `a` → `b` (not directional).
///
/// A key that is not a [`FiveTupleKey`] (a host, a counter key) yields no
/// endpoints unless they are set explicitly.
pub struct AnomalyWriter<'sink> {
    sink: &'sink mut dyn AnomalySink,
    kind: &'static str,
    severity: Severity,
    ts: Timestamp,
    key: Option<&'sink dyn Key>,
    endpoints: Option<Endpoints>,
    initiator: Option<Orientation>,
    /// The flow `Ctx::emit` was called for, with its initiator.
    current_flow: Option<(FiveTupleKey, Orientation)>,
    obs: ArrayVec<(&'static str, Cow<'sink, str>), ANOMALY_INLINE_CAPACITY>,
    metrics: ArrayVec<(&'static str, f64), ANOMALY_INLINE_CAPACITY>,
}

impl<'sink> AnomalyWriter<'sink> {
    /// `pub(crate)` constructor — user code starts a writer via
    /// [`AnomalySink::begin`].
    pub(crate) fn new(
        sink: &'sink mut dyn AnomalySink,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> Self {
        Self {
            sink,
            kind,
            severity,
            ts,
            key: None,
            endpoints: None,
            initiator: None,
            current_flow: None,
            obs: ArrayVec::new(),
            metrics: ArrayVec::new(),
        }
    }

    /// Record the flow the emitting handler runs for and its initiator
    /// ([`Ctx::emit`](crate::ctx::Ctx::emit)), so a key that is this flow
    /// resolves to directional endpoints.
    pub(crate) fn in_flow(mut self, key: FiveTupleKey, initiator: Orientation) -> Self {
        self.current_flow = Some((key, initiator));
        self
    }

    /// Attach a key — typically a flow key (`FiveTupleKey`) or a
    /// host (`IpAddr`). Held as `&dyn Key` so the writer stays
    /// key-erased; sinks get its `Debug` rendering and, for a flow key,
    /// the [`Endpoints`] (see the type docs for how they are oriented).
    pub fn with_key<K: Key>(mut self, key: &'sink K) -> Self {
        let erased: &dyn Key = key;
        self.key = Some(erased);
        self
    }

    /// Attach a flow key and the orientation of its initiator (the
    /// endpoint that opened it: `Forward` = `key.a`; e.g.
    /// [`flowscope::FlowStats::initiator_orientation`] or
    /// [`Ctx::initiator`](crate::ctx::Ctx::initiator)). The sink sees
    /// `src` = the initiator. New in 0.32.0.
    pub fn with_flow(self, key: &'sink FiveTupleKey, initiator: Orientation) -> Self {
        self.with_key(key).with_initiator(initiator)
    }

    /// Say which endpoint of the attached flow key is the initiator (or
    /// the anomaly's subject) — `Forward`: `key.a`. Ignored for a key that
    /// is not a [`FiveTupleKey`]. New in 0.32.0.
    pub fn with_initiator(mut self, initiator: Orientation) -> Self {
        self.initiator = Some(initiator);
        self
    }

    /// Set the endpoints outright (e.g. a host-pair anomaly with no flow
    /// key). Overrides whatever the key would give. New in 0.32.0.
    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// The endpoints the sink receives — see the type docs.
    fn resolve_endpoints(&self) -> Option<Endpoints> {
        if self.endpoints.is_some() {
            return self.endpoints;
        }
        let key = self.key?.as_any().downcast_ref::<FiveTupleKey>()?;
        if let Some(initiator) = self.initiator {
            return Some(Endpoints::from_flow(key, initiator));
        }
        if let Some((flow, initiator)) = &self.current_flow
            && flow.proto == key.proto
        {
            let (i, r) = flow.oriented(*initiator);
            if (key.a, key.b) == (i, r) || (key.a, key.b) == (r, i) {
                return Some(Endpoints::new(i, r, key.proto_str(), true));
            }
        }
        Some(Endpoints::canonical(key))
    }

    /// Attach a textual observation. `&'static str` literals pass
    /// through with zero allocation; `String` values become
    /// `Cow::Owned` (one allocation).
    ///
    /// Drops silently past [`ANOMALY_INLINE_CAPACITY`] entries.
    pub fn with(mut self, label: &'static str, value: impl Into<Cow<'sink, str>>) -> Self {
        let _ = self.obs.try_push((label, value.into()));
        self
    }

    /// Attach a textual observation with a **runtime-computed label**.
    /// 0.21 A.5: escape hatch for the case where the label can't be
    /// a `&'static str` literal — `format!("attempt_{i}")` or one of
    /// `["method", "path", "host"]` picked at runtime.
    ///
    /// The label is leaked via [`Box::leak`] so it satisfies the
    /// inner storage's `&'static str` slot. Costs **one heap
    /// allocation per emit AND permanent process memory** —
    /// genuinely a hot-path foot-gun if used naively. Prefer
    /// [`Self::with`] with a small const lookup table when the
    /// labels are bounded.
    pub fn with_dynamic(self, label: impl Into<String>, value: impl Into<Cow<'sink, str>>) -> Self {
        let leaked: &'static str = Box::leak(label.into().into_boxed_str());
        self.with(leaked, value)
    }

    /// Attach a numeric metric. Drops silently past
    /// [`ANOMALY_INLINE_CAPACITY`] entries.
    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self {
        let _ = self.metrics.try_push((label, value));
        self
    }

    /// Finalize and ship to the underlying sink.
    pub fn emit(self) {
        let endpoints = self.resolve_endpoints();
        let record = AnomalyRecord {
            kind: self.kind,
            severity: self.severity,
            ts: self.ts,
            key: self.key,
            endpoints,
            observations: &self.obs,
            metrics: &self.metrics,
        };
        self.sink.write(&record);
    }

    /// Materialize as a [`flowscope::OwnedAnomaly`] instead of
    /// firing the sink. The writer's accumulated state — kind,
    /// severity, ts, observations, metrics — is folded into the
    /// returned owned value; its 5-tuple fields are the
    /// [`Endpoints`] [`Self::emit`] would hand the sink (initiator
    /// first when known).
    ///
    /// Use when retaining the anomaly past the dispatch frame
    /// (batch upload, cross-task channel, custom sink) without
    /// involving an intermediate [`AnomalySink`]. The caller owns
    /// what happens next; no sink callback is invoked.
    pub fn emit_owned(self) -> flowscope::OwnedAnomaly {
        AnomalyRecord {
            kind: self.kind,
            severity: self.severity,
            ts: self.ts,
            key: self.key,
            endpoints: self.resolve_endpoints(),
            observations: &self.obs,
            metrics: &self.metrics,
        }
        .to_owned_anomaly()
    }

    /// Number of observations queued. Useful for the saturation
    /// tests + diagnostics.
    pub fn observation_count(&self) -> usize {
        self.obs.len()
    }

    /// Number of metrics queued.
    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }
}

/// No-op sink — the default when no `.sink(...)` is set on the
/// [`crate::monitor::MonitorBuilder`].
pub struct NoopSink;

impl AnomalySink for NoopSink {
    fn write(&mut self, _record: &AnomalyRecord<'_>) {}
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    /// Test sink that records every call into a shared buffer so
    /// assertions can inspect the writer's output without going
    /// through stdout.
    #[derive(Default)]
    struct CaptureSink {
        calls: Rc<RefCell<Vec<CapturedCall>>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct CapturedCall {
        kind: &'static str,
        severity: Severity,
        obs_count: usize,
        metric_count: usize,
        has_key: bool,
        endpoints: Option<Endpoints>,
    }

    // SAFETY: CaptureSink uses Rc<RefCell<_>> internally — it's
    // !Sync — but Send is fine because the test never hands it
    // across threads. The Send claim is required by AnomalySink.
    unsafe impl Send for CaptureSink {}

    impl AnomalySink for CaptureSink {
        fn write(&mut self, r: &AnomalyRecord<'_>) {
            self.calls.borrow_mut().push(CapturedCall {
                kind: r.kind,
                severity: r.severity,
                obs_count: r.observations.len(),
                metric_count: r.metrics.len(),
                has_key: r.key.is_some(),
                endpoints: r.endpoints,
            });
        }
    }

    #[test]
    fn noop_sink_is_object_safe_and_zero_cost() {
        let mut sink = NoopSink;
        let s: &mut dyn AnomalySink = &mut sink;
        // Object-safe: this only compiles if AnomalySink is dyn-safe.
        s.write(&AnomalyRecord::new(
            "k",
            Severity::Info,
            Timestamp::new(0, 0),
        ));
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// 10.0.0.9:40000 opened a connection to 10.0.0.1:80; the key sorts
    /// the server first, so the initiator is `Reverse`.
    fn server_first_key() -> FiveTupleKey {
        FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            sock("10.0.0.1:80"),
            sock("10.0.0.9:40000"),
        )
    }

    fn endpoints_of(build: impl FnOnce(&mut CaptureSink)) -> Option<Endpoints> {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        build(&mut sink);
        let calls = calls.borrow();
        assert_eq!(calls.len(), 1);
        calls[0].endpoints
    }

    /// #215: `with_flow` reads the key from its initiator.
    #[test]
    fn with_flow_puts_the_initiator_first() {
        let key = server_first_key();
        let e = endpoints_of(|s| {
            s.begin("K", Severity::Info, Timestamp::new(0, 0))
                .with_flow(&key, Orientation::Reverse)
                .emit()
        })
        .unwrap();
        assert_eq!(e.src(), Some(sock("10.0.0.9:40000")));
        assert_eq!(e.dest(), Some(sock("10.0.0.1:80")));
        assert_eq!(e.proto, Some("TCP"));
        assert!(e.directional);
    }

    /// A key alone is read as stored and marked non-directional.
    #[test]
    fn a_bare_flow_key_is_canonical() {
        let key = server_first_key();
        let e = endpoints_of(|s| {
            s.begin("K", Severity::Info, Timestamp::new(0, 0))
                .with_key(&key)
                .emit()
        })
        .unwrap();
        assert_eq!(e.src(), Some(key.a));
        assert!(!e.directional);
    }

    /// The flow `Ctx::emit` ran for orients its own key — stored either
    /// way round — and leaves any other key alone.
    #[test]
    fn the_current_flow_orients_its_own_key_only() {
        let key = server_first_key();
        let swapped = FiveTupleKey::new(key.proto, key.b, key.a);
        let other = FiveTupleKey::new(key.proto, key.a, sock("10.0.0.9:40001"));
        for k in [key, swapped] {
            let e = endpoints_of(|s| {
                s.begin("K", Severity::Info, Timestamp::new(0, 0))
                    .in_flow(key, Orientation::Reverse)
                    .with_key(&k)
                    .emit()
            })
            .unwrap();
            assert_eq!(e.src(), Some(sock("10.0.0.9:40000")), "{k:?}");
            assert!(e.directional);
        }
        let e = endpoints_of(|s| {
            s.begin("K", Severity::Info, Timestamp::new(0, 0))
                .in_flow(key, Orientation::Reverse)
                .with_key(&other)
                .emit()
        })
        .unwrap();
        assert_eq!(e, Endpoints::canonical(&other));
        // No key → no endpoints, current flow or not.
        let none = endpoints_of(|s| {
            s.begin("K", Severity::Info, Timestamp::new(0, 0))
                .in_flow(key, Orientation::Reverse)
                .emit()
        });
        assert_eq!(none, None);
    }

    /// Explicit endpoints win; a non-flow key yields none.
    #[test]
    fn explicit_endpoints_win_and_host_keys_have_none() {
        let key = server_first_key();
        let set = Endpoints::new(sock("192.0.2.1:1"), sock("192.0.2.2:2"), Some("UDP"), true);
        let e = endpoints_of(|s| {
            s.begin("K", Severity::Info, Timestamp::new(0, 0))
                .with_flow(&key, Orientation::Forward)
                .with_endpoints(set)
                .emit()
        });
        assert_eq!(e, Some(set));
        let host: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        let e = endpoints_of(|s| {
            s.begin("K", Severity::Info, Timestamp::new(0, 0))
                .with_key(&host)
                .with_initiator(Orientation::Forward)
                .emit()
        });
        assert_eq!(e, None);
    }

    /// `emit_owned` and `publish_owned` carry the same orientation.
    #[test]
    fn owned_round_trip_keeps_the_initiator_first() {
        let key = server_first_key();
        let mut sink = NoopSink;
        let owned = sink
            .begin("K", Severity::Info, Timestamp::new(0, 0))
            .with_flow(&key, Orientation::Reverse)
            .emit_owned();
        assert_eq!(
            (owned.src_ip, owned.src_port),
            (Some(key.b.ip()), Some(key.b.port()))
        );
        let mut cap = CaptureSink::default();
        let calls = Rc::clone(&cap.calls);
        publish_owned(&mut cap, &owned);
        let e = calls.borrow()[0].endpoints.unwrap();
        assert_eq!(e.src(), Some(key.b));
        assert_eq!(e.dest(), Some(key.a));
        assert!(e.directional);
        // Nothing to say → no endpoints.
        let bare = flowscope::OwnedAnomaly::new(
            flowscope::DetectorKind::Other("x"),
            flowscope::event::Severity::Info,
            Timestamp::new(0, 0),
        );
        assert_eq!(Endpoints::from_owned(&bare), None);
    }

    /// A hand-built record: `with_key` fills canonical endpoints unless
    /// set; `to_owned_anomaly` copies them.
    #[test]
    fn record_builder_and_owned_copy() {
        let key = server_first_key();
        let obs = [("note", Cow::Borrowed("x"))];
        let r = AnomalyRecord::new("K", Severity::Warning, Timestamp::new(3, 0))
            .with_key(&key)
            .with_observations(&obs)
            .with_metrics(&[("m", 1.0)]);
        assert_eq!(r.endpoints, Some(Endpoints::canonical(&key)));
        assert_eq!(r.flow_key(), Some(&key));
        let owned = r.to_owned_anomaly();
        assert_eq!(owned.src_ip, Some(key.a.ip()));
        assert_eq!(owned.observations[0].1.as_ref(), "x");
        assert_eq!(owned.metrics[0], ("m", 1.0));
        let flipped = AnomalyRecord::new("K", Severity::Info, Timestamp::new(0, 0))
            .with_endpoints(Endpoints::from_flow(&key, Orientation::Reverse))
            .with_key(&key);
        assert_eq!(flipped.to_owned_anomaly().src_port, Some(40_000));
    }

    /// Sink that records the observation key/value pairs it receives.
    #[derive(Default)]
    struct ObsSink {
        obs: Vec<(&'static str, String)>,
    }
    unsafe impl Send for ObsSink {}
    impl AnomalySink for ObsSink {
        fn write(&mut self, r: &AnomalyRecord<'_>) {
            self.obs
                .extend(r.observations.iter().map(|(k, v)| (*k, v.to_string())));
        }
    }

    #[test]
    fn publish_owned_appends_attack_technique_for_kinded_anomaly() {
        // A beacon-kinded anomaly maps to ATT&CK T1071 — publish_owned must
        // surface it as an `attack_technique` observation (issue #127).
        let owned = flowscope::OwnedAnomaly::new(
            flowscope::DetectorKind::BeaconRita,
            flowscope::event::Severity::Warning,
            Timestamp::new(0, 0),
        );
        let mut sink = ObsSink::default();
        publish_owned(&mut sink, &owned);
        assert!(
            sink.obs
                .iter()
                .any(|(k, v)| *k == "attack_technique" && v == "T1071"),
            "expected attack_technique=T1071, got {:?}",
            sink.obs
        );
    }

    #[test]
    fn publish_owned_omits_attack_technique_for_untagged_kind() {
        // `Other(_)` has no technique — no spurious observation.
        let owned = flowscope::OwnedAnomaly::new(
            flowscope::DetectorKind::Other("custom"),
            flowscope::event::Severity::Info,
            Timestamp::new(0, 0),
        );
        let mut sink = ObsSink::default();
        publish_owned(&mut sink, &owned);
        assert!(
            !sink.obs.iter().any(|(k, _)| *k == "attack_technique"),
            "unexpected attack_technique for Other kind: {:?}",
            sink.obs
        );
    }

    #[test]
    fn writer_records_kind_severity_and_counts() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        sink.begin("TestKind", Severity::Warning, Timestamp::new(1, 0))
            .with("note", "hi")
            .with_metric("count", 7.0)
            .emit();
        let calls = calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, "TestKind");
        assert_eq!(calls[0].severity, Severity::Warning);
        assert_eq!(calls[0].obs_count, 1);
        assert_eq!(calls[0].metric_count, 1);
        assert!(!calls[0].has_key);
    }

    #[test]
    fn writer_with_key_marks_has_key() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        let key = 42u32;
        sink.begin("WithKey", Severity::Info, Timestamp::new(0, 0))
            .with_key(&key)
            .emit();
        assert!(calls.borrow()[0].has_key);
    }

    #[test]
    fn writer_drops_extra_observations_past_capacity() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        // Static slug labels — the test exercises that they pass
        // through `with` without allocating per call.
        const LABELS: [&str; ANOMALY_INLINE_CAPACITY + 4] =
            ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"];
        let mut w = sink.begin("Sat", Severity::Info, Timestamp::new(0, 0));
        for label in &LABELS {
            w = w.with(label, "v");
        }
        w.emit();
        let calls = calls.borrow();
        assert_eq!(
            calls[0].obs_count, ANOMALY_INLINE_CAPACITY,
            "writer must cap observations at ANOMALY_INLINE_CAPACITY"
        );
    }

    #[test]
    fn writer_drops_extra_metrics_past_capacity() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        let mut w = sink.begin("Sat", Severity::Info, Timestamp::new(0, 0));
        for _ in 0..(ANOMALY_INLINE_CAPACITY + 4) {
            w = w.with_metric("m", 1.0);
        }
        w.emit();
        assert_eq!(calls.borrow()[0].metric_count, ANOMALY_INLINE_CAPACITY);
    }

    #[test]
    fn writer_emit_owned_materializes_without_firing_sink() {
        let mut sink = NoopSink;
        let owned = sink
            .begin("Materialize", Severity::Warning, Timestamp::new(7, 0))
            .with("note", "captured")
            .with_metric("rate", 4.5)
            .emit_owned();
        // Same `kind`, severity-mapped to flowscope's enum, ts intact.
        assert_eq!(owned.kind.as_str(), "Materialize");
        assert_eq!(owned.severity, flowscope::event::Severity::Warning);
        assert_eq!(owned.ts, Timestamp::new(7, 0));
        // Observation + metric round-tripped.
        assert_eq!(owned.observations.len(), 1);
        assert_eq!(owned.observations[0].0, "note");
        assert_eq!(owned.observations[0].1.as_ref(), "captured");
        assert_eq!(owned.metrics[0], ("rate", 4.5));
        // No key attached → 5-tuple fields default to None.
        assert!(owned.src_ip.is_none() && owned.dest_ip.is_none());
    }

    #[test]
    fn writer_emit_owned_with_five_tuple_key_populates_structured_fields() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        );
        let mut sink = NoopSink;
        let owned = sink
            .begin("PortScan", Severity::Error, Timestamp::new(0, 0))
            .with_key(&key)
            .emit_owned();
        // KeyFields downcast populated the 5-tuple fields.
        assert_eq!(owned.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(owned.src_port, Some(12345));
        assert_eq!(owned.dest_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(owned.dest_port, Some(443));
        assert_eq!(owned.proto, Some("TCP"));
    }

    #[test]
    fn writer_with_dynamic_leaks_label_to_static() {
        // 0.21 A.5: `with_dynamic` lets the label be runtime-built
        // by leaking it. Verify the rendered string is observable
        // on the captured call.
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        sink.begin("DynLabel", Severity::Info, Timestamp::new(0, 0))
            .with_dynamic(format!("attempt_{}", 3), "captured")
            .emit();
        let recorded = &calls.borrow()[0];
        assert_eq!(recorded.obs_count, 1);
    }

    #[test]
    fn writer_static_str_value_stays_borrowed() {
        let mut sink = CaptureSink::default();
        let mut w = sink.begin("S", Severity::Info, Timestamp::new(0, 0));
        w = w.with("k", "static-literal");
        // Static literal must remain a `Cow::Borrowed`, never an `Owned`.
        match &w.obs[0].1 {
            Cow::Borrowed(_) => {}
            Cow::Owned(_) => panic!("static literal should not allocate"),
        }
        w.emit();
    }

    #[test]
    fn writer_counts_helpers() {
        let mut sink = NoopSink;
        let w = sink
            .begin("X", Severity::Info, Timestamp::new(0, 0))
            .with("a", "v")
            .with_metric("m", 1.0);
        assert_eq!(w.observation_count(), 1);
        assert_eq!(w.metric_count(), 1);
        w.emit();
    }
}
