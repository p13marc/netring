//! Async **read + effect** handlers (0.25 Phase B1).
//!
//! The 0.24 `on_async` handler sees only `&E::Payload` — it can't read
//! monitor state (`Ctx`) because the HRTB lifetime gymnastics over
//! `Ctx<'a>` didn't compose. This module is the redesign (architecture
//! §5): an async handler that **reads `Ctx` synchronously** and **writes
//! back via a typed [`Effects`] value** the run loop applies after the
//! batch — read access (sync, `&Ctx`), then I/O, then a deferred write
//! ([`Effects`]).
//!
//! The handler closure never captures `Ctx` (the returned future is `'static`).
//! The dispatcher's apply phase *does* hold `&mut Ctx` across the `.await` (to
//! write [`Effects`] back to the sink afterwards) — that is `Send`-safe **only
//! because every field of [`Ctx`] is `Send`** (notably
//! `AnomalySink: Send`). The `Send`-ness of the run loop therefore rests on
//! `Ctx: Send`, *not* on releasing `&mut Ctx` before the await; if a `!Send`
//! field is ever added to `Ctx`, the effect path stops being `Send` (guarded
//! by `run_loop_future_is_spawnable` in `tests/monitor_send.rs`, which
//! registers an `on_effect` handler precisely to keep this honest).
//!
//! ```ignore
//! .on_effect::<FlowStarted<Tcp>>(|evt, ctx| {
//!     let key = ctx.flow;                 // read Ctx synchronously
//!     async move {                        // 'static future — owns `key`
//!         let verdict = lookup_threat_intel(key).await?;   // do I/O
//!         Ok(Effects::emit(Anomaly::new("ioc", Severity::Warning)))  // write back
//!     }
//! })
//! ```
//!
//! ## The blanket-impl shape (validated)
//!
//! The load-bearing question (plan B1) was whether
//! `F: Fn(&E::Payload, &Ctx<'_>) -> Fut where Fut: 'static` unifies in
//! stable Rust — the closure takes two references but returns a future
//! that captures neither (it `move`s owned data out of `Ctx`). It does;
//! the test below registers exactly that shape. (If it had not, the
//! fallback was a by-value `Send` `CtxSnapshot`.)

use std::future::Future;

use crate::anomaly::OwnedAnomaly;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::monitor::async_handler::BoxFuture;
use crate::protocol::event_typed::Event;

/// A typed list of deferred mutations an async [`EffectHandler`] returns;
/// the run loop applies them **synchronously after the batch is drained**
/// (so no `&mut Ctx` is held across an `.await`).
///
/// 0.25-B1 ships the `emit` effect (the common case — react to an event,
/// do I/O, raise an anomaly). `set_state::<T>` / `counter` / `enqueue`
/// land in a follow-up; the type is `#[non_exhaustive]`-friendly via the
/// constructor/builder surface, so adding them is additive.
#[derive(Debug, Default)]
#[must_use = "Effects do nothing unless returned from an EffectHandler"]
pub struct Effects {
    /// Anomalies to emit through the monitor's sink after the batch.
    pub(crate) anomalies: Vec<OwnedAnomaly>,
}

impl Effects {
    /// No effect — the handler did I/O but has nothing to write back.
    pub fn none() -> Self {
        Self::default()
    }

    /// Emit one anomaly. Build the [`OwnedAnomaly`] with
    /// [`OwnedAnomaly::new`](flowscope::OwnedAnomaly) + its `with_*`
    /// setters, or via [`crate::anomaly::sink::AnomalyWriter`]-style code.
    pub fn emit(anomaly: OwnedAnomaly) -> Self {
        Self {
            anomalies: vec![anomaly],
        }
    }

    /// Add another anomaly to this effect set (chainable).
    pub fn and_emit(mut self, anomaly: OwnedAnomaly) -> Self {
        self.anomalies.push(anomaly);
        self
    }

    /// `true` if there's nothing to apply (the run loop can skip the
    /// apply step entirely).
    pub fn is_empty(&self) -> bool {
        self.anomalies.is_empty()
    }

    /// Merge another effect set into this one.
    pub fn extend(&mut self, other: Effects) {
        self.anomalies.extend(other.anomalies);
    }

    /// Apply the effects to the monitor's anomaly sink. Called by
    /// `Dispatcher::dispatch_effects` after the batch is drained (the
    /// `&mut Ctx` write phase).
    pub(crate) fn apply(self, sink: &mut dyn crate::anomaly::sink::AnomalySink) {
        for anomaly in self.anomalies {
            apply_owned_anomaly(sink, anomaly);
        }
    }
}

/// Write one [`OwnedAnomaly`] to a `&mut dyn AnomalySink`. The anomaly's
/// 5-tuple fields become the record's endpoints as they are (directional:
/// `src` is whoever the anomaly put there — flowscope and
/// [`AnomalyWriter::emit_owned`](crate::anomaly::sink::AnomalyWriter::emit_owned)
/// put the flow's initiator); a complete 5-tuple is also attached as the
/// flow key, in its canonical (address-sorted) form.
fn apply_owned_anomaly(sink: &mut dyn crate::anomaly::sink::AnomalySink, a: OwnedAnomaly) {
    use std::borrow::Cow;
    use std::net::SocketAddr;

    use crate::anomaly::sink::{AnomalyRecord, Endpoints};

    // `write` wants a `&'static str` kind. flowscope 0.22: `OwnedAnomaly::kind`
    // is a typed `DetectorKind` whose `as_str()` is `&'static str` for every
    // variant.
    let kind: &'static str = a.kind.as_str();

    // Reconstruct the flow key when the anomaly carries a full 5-tuple
    // (the common case for flow/session anomalies). Incomplete → no key.
    let key: Option<flowscope::extract::FiveTupleKey> = match (
        a.src_ip,
        a.src_port,
        a.dest_ip,
        a.dest_port,
        a.proto.and_then(l4proto_from_str),
    ) {
        (Some(sip), Some(sp), Some(dip), Some(dp), Some(proto)) => Some(
            flowscope::extract::FiveTupleKey::new(
                proto,
                SocketAddr::new(sip, sp),
                SocketAddr::new(dip, dp),
            )
            .canonical()
            .0,
        ),
        _ => None,
    };

    // Observations re-borrow as `Cow::Borrowed` (no clone of the values).
    let observations: Vec<(&'static str, Cow<'_, str>)> = a
        .observations
        .iter()
        .map(|(l, v)| (*l, Cow::Borrowed(v.as_ref())))
        .collect();

    let mut record = AnomalyRecord::new(kind, a.severity.into(), a.ts)
        .with_observations(&observations)
        .with_metrics(&a.metrics);
    if let Some(k) = &key {
        record = record.with_key(k);
    }
    record.endpoints = Endpoints::from_owned(&a);
    sink.write(&record);
}

/// Map an `OwnedAnomaly::proto` label back to an `L4Proto` for key
/// reconstruction. Unknown → `None` (the key is then omitted).
fn l4proto_from_str(p: &str) -> Option<flowscope::L4Proto> {
    use flowscope::L4Proto;
    match p {
        "tcp" | "TCP" => Some(L4Proto::Tcp),
        "udp" | "UDP" => Some(L4Proto::Udp),
        "icmp" | "ICMP" => Some(L4Proto::Icmp),
        "icmpv6" | "ICMPv6" | "icmp6" | "ipv6-icmp" | "IPv6-ICMP" => Some(L4Proto::IcmpV6),
        "sctp" | "SCTP" => Some(L4Proto::Sctp),
        _ => None,
    }
}

/// An async handler that reads `&Ctx` synchronously and returns a
/// `'static` future resolving to [`Effects`]. The 0.25 successor to
/// [`AsyncHandler`](crate::monitor::AsyncHandler) (which is payload-only).
///
/// Registered via `MonitorBuilder::on_effect` (0.25-B1 wiring).
pub trait EffectHandler<E: Event>: Send + Sync + 'static {
    /// Build the handler's future. `ctx` is borrowed only for the
    /// synchronous body; the returned future is `'static` and must not
    /// capture it.
    fn call(&self, payload: &E::Payload, ctx: &Ctx<'_>) -> BoxFuture<Result<Effects>>;
}

/// Blanket impl over `Fn(&E::Payload, &Ctx<'_>) -> Fut`. `Fut: Send +
/// 'static` keeps the run-loop future `Send`; the closure reads `ctx`
/// in its synchronous prologue and `move`s owned data into `Fut`.
impl<E, F, Fut> EffectHandler<E> for F
where
    E: Event,
    F: Fn(&E::Payload, &Ctx<'_>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Effects>> + Send + 'static,
{
    #[inline]
    fn call(&self, payload: &E::Payload, ctx: &Ctx<'_>) -> BoxFuture<Result<Effects>> {
        Box::pin(self(payload, ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::Severity;
    use crate::anomaly::sink::NoopSink;
    use crate::ctx::{CounterRegistry, StateMap};
    use crate::protocol::builtin::Tcp;
    use crate::protocol::event_typed::FlowStarted;
    use flowscope::Timestamp;

    fn dummy_evt() -> FlowStarted<Tcp> {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        );
        FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
    }

    fn fresh_ctx<'a>(
        state: &'a mut StateMap,
        sink: &'a mut NoopSink,
        counters: &'a mut CounterRegistry,
        flow_states: &'a mut crate::ctx::FlowStateRegistry,
    ) -> Ctx<'a> {
        Ctx {
            flow: Some(flowscope::extract::FiveTupleKey::new(
                flowscope::L4Proto::Tcp,
                "10.0.0.1:1".parse().unwrap(),
                "10.0.0.2:80".parse().unwrap(),
            )),
            ts: Timestamp::new(0, 0),
            source: None,
            monitor_name: None,
            state_map: state,
            sink,
            counters,
            flow_states,
            label_table: crate::ctx::default_label_table(),
            tracker: None,
            arp_table: None,
            side: None,
            orientation: None,
            initiator: None,
        }
    }

    // THE COMPILE PROBE (plan B1): a closure that takes (&Payload, &Ctx),
    // reads Ctx synchronously, and returns a 'static future that owns the
    // extracted data. If this registers + runs, the two-lifetime blanket
    // impl unifies in stable Rust and the design is viable.
    #[tokio::test(flavor = "current_thread")]
    async fn effect_handler_reads_ctx_sync_then_returns_static_future() {
        let handler = |_evt: &FlowStarted<Tcp>, ctx: &Ctx<'_>| {
            // Synchronous read of Ctx → owned data moved into the future.
            let key = ctx.flow;
            let ts = ctx.ts;
            async move {
                tokio::task::yield_now().await; // simulate I/O
                // `key`/`ts` are owned here; no borrow of Ctx survived.
                let mut a = OwnedAnomaly::new(
                    flowscope::DetectorKind::Other("probe"),
                    Severity::Info.into(),
                    ts,
                );
                if let Some(k) = key {
                    a = a.with_key(&k);
                }
                Ok(Effects::emit(a))
            }
        };

        let mut s = StateMap::default();
        let mut sink = NoopSink;
        let mut c = CounterRegistry::default();
        let mut fs = crate::ctx::FlowStateRegistry::default();
        let ctx = fresh_ctx(&mut s, &mut sink, &mut c, &mut fs);
        let evt = dummy_evt();

        let effects = EffectHandler::<FlowStarted<Tcp>>::call(&handler, &evt, &ctx)
            .await
            .unwrap();
        assert_eq!(effects.anomalies.len(), 1);
        assert!(!effects.is_empty());
    }

    #[test]
    fn apply_writes_anomalies_to_the_sink_preserving_kind_and_reconstructed_key() {
        use crate::anomaly::sink::{AnomalyRecord, AnomalySink, Endpoints};

        // A sink that records what `write` received.
        #[derive(Default)]
        struct Capturing {
            // (kind, key, endpoints, obs_count)
            writes: Vec<(
                &'static str,
                Option<flowscope::extract::FiveTupleKey>,
                Option<Endpoints>,
                usize,
            )>,
        }
        impl AnomalySink for Capturing {
            fn write(&mut self, r: &AnomalyRecord<'_>) {
                self.writes.push((
                    r.kind,
                    r.flow_key().copied(),
                    r.endpoints,
                    r.observations.len(),
                ));
            }
        }

        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:1234".parse().unwrap(),
        );
        // 10.0.0.2 opened the flow: the anomaly reads it from there.
        let anomaly = OwnedAnomaly::new(
            flowscope::DetectorKind::Other("ioc_match"),
            Severity::Critical.into(),
            Timestamp::new(0, 0),
        )
        .with_flow(&key, flowscope::Orientation::Reverse)
        .with_observation("ja4", "t13d1516h2");

        let mut sink = Capturing::default();
        Effects::emit(anomaly).apply(&mut sink);

        assert_eq!(sink.writes.len(), 1);
        let (kind, got_key, endpoints, obs) = sink.writes[0];
        assert_eq!(kind, "ioc_match");
        // The complete 5-tuple is reconstructed into the canonical key …
        assert_eq!(got_key, Some(key));
        // … and the endpoints keep the anomaly's direction (#215).
        let e = endpoints.expect("endpoints");
        assert_eq!(e.src(), Some(key.b));
        assert_eq!(e.dest(), Some(key.a));
        assert!(e.directional);
        assert_eq!(obs, 1);
    }

    #[test]
    fn effects_builder_merges_and_reports_empty() {
        assert!(Effects::none().is_empty());
        let ts = Timestamp::new(0, 0);
        let mut e = Effects::emit(OwnedAnomaly::new(
            flowscope::DetectorKind::Other("a"),
            Severity::Info.into(),
            ts,
        ))
        .and_emit(OwnedAnomaly::new(
            flowscope::DetectorKind::Other("b"),
            Severity::Warning.into(),
            ts,
        ));
        assert_eq!(e.anomalies.len(), 2);
        e.extend(Effects::emit(OwnedAnomaly::new(
            flowscope::DetectorKind::Other("c"),
            Severity::Error.into(),
            ts,
        )));
        assert_eq!(e.anomalies.len(), 3);
    }
}
