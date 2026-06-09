# netring 0.20 — Phase B: Handler trait + Ctx + Dispatcher + Monitor builder skeleton

**Effort:** 4–6 days
**Predecessor:** [`Phase A`](./netring-0.20-phase-A-protocol-trait.md) — Protocol trait + Event types
**Successor:** [`Phase C`](./netring-0.20-phase-C-perf-hardening.md) — perf hardening + AnomalyWriter

## 1. Goal

The intellectual core of the redesign. After this phase:

- A `Handler<E, M>` trait exists with axum-style blanket impls over `Fn(&E::Payload, ...) -> Result<()>` closures for 0–8 extractor parameters.
- A `Ctx<'a>` struct + `FromCtx` trait + standard extractors (`State<T>`, `Sink<A>`, `Now`, `Counter<K>`) exist.
- A `Dispatcher` with `TypeId`-keyed handler storage exists; dispatch is array-indexed after build.
- A `Monitor` builder skeleton exists with `.protocol::<P>()` + `.on::<E>(handler)` + `.state::<T>()` registration methods.
- The `Monitor` wires flowscope's typed `Driver<E>` + per-slot `SlotHandle<M, K>` through the dispatcher to user-registered closures.
- **Sync handlers only** — the `on_async` escape hatch is Phase D.

After this phase a *minimal* monitor compiles and runs end-to-end:

```rust
Monitor::builder()
    .interfaces(["eth0"])
    .protocol::<Http>()
    .on::<HttpRequest>(|req: &HttpMessage| {
        println!("{:?}", req);
        Ok(())
    })
    .build()?
    .run_for(Duration::from_secs(60))
    .await?;
```

No middleware, no async handlers, no `detector!` macro yet. Those land in D/E.

## 2. Scope

### In
- `Handler<E, M>` trait + `impl_handler!` macro (0–8 extractors).
- `Ctx<'a>` struct + `FromCtx` trait + `StateMap` + `CounterRegistry`.
- Standard extractors: `State<T>`, `Sink<A>` (stub — full impl in Phase C), `Now`, `Counter<K>`.
- `Dispatcher` with `TypeId`-keyed slots, array-indexed dispatch.
- `HandlerRegistry` — build-side registry that freezes into `Dispatcher`.
- `Monitor` + `MonitorBuilder` with: `interfaces(...)`, `protocol::<P>()`, `on::<E>(handler)`, `state::<T>()`, `counter::<K>(...)`, `sink(...)`, `tick(...)`, `build()`, `run_until(...)`, `run_for(...)`, `run_until_signal()`.
- `TypedProtocolSlot<P>` wrapper around flowscope's `SlotHandle<P::Message, K>`.
- The `run_loop` that calls `Driver::track_into` + drains slot handles + dispatches.
- `compile-fail` tests via `trybuild` for borrow conflicts.

### Out
- `Anomaly`-emission API on `Sink<A>` — defined as a stub here, fully implemented in Phase C.
- Async handlers — Phase D.
- `Layer` middleware — Phase D.
- `detector!` macro — Phase E.
- Multi-interface beyond a single-element `Vec<String>` — Phase E.
- Per-CPU sharding — Phase F.
- `Ctx::split_*` projection helpers — Phase C (alongside the perf work).

## 3. Dependencies

- Phase A complete: `Protocol` trait + 7 builtin markers + `Event` trait + typed event structs.
- `bon` crate added to dependencies (this phase's `Cargo.toml` deltas).
- `rustc-hash` crate added (for `TypeId`-keyed registry; `FxHashMap` is the active maintained source).
- `arrayvec` crate added (for `ArrayVec<(TypeId, u8), 16>` in `Dispatcher`).

## 4. Module layout

```
src/
├── ctx/                          A
│   ├── mod.rs                    A  — Ctx<'a> struct + SourceIdx
│   ├── from_ctx.rs               A  — FromCtx trait + StateMap + CounterRegistry
│   └── extractors.rs             A  — State<T>, Sink<A>, Now, Counter<K>
│
├── monitor/                      A
│   ├── mod.rs                    A  — Monitor + MonitorBuilder + run modes
│   ├── handler.rs                A  — Handler trait + impl_handler! macro
│   ├── dispatcher.rs             A  — Dispatcher, slot array dispatch
│   ├── registry.rs               A  — HandlerRegistry + ProtocolRegistry + slot wrapping
│   ├── run.rs                    A  — run_loop + lifecycle event translation
│   └── tick.rs                   A  — periodic tick handler plumbing
│
├── error.rs                      M  — add BuildError variants
├── lib.rs                        M  — pub mod ctx; pub mod monitor; re-exports
│
tests/
├── handler_blanket.rs            A  — 0..8 extractor arities compile + run
├── ctx_borrow.rs                 A  — borrow-checker honesty tests
├── dispatcher_typeid.rs          A  — TypeId routing correctness
├── monitor_e2e.rs                A  — synthetic events → handler invocation
└── ui/                           A  — trybuild compile-fail tests
    ├── borrow_conflict.rs        A  — &mut Sink + &mut State<Same field> rejected
    ├── too_many_extractors.rs    A  — 9 extractors fails to compile
    └── missing_state_register.rs A  — State<T> without prior .state::<T>() panics at runtime; compiles fine
```

**LoC estimates:** ~1,600 LoC new across these files (~600 LoC in `handler.rs` after macro expansion, ~400 LoC dispatcher + registry + run loop, ~300 LoC Ctx + extractors, ~300 LoC tests).

## 5. Detailed deliverables

### 5.1 `Cargo.toml` additions

```toml
[dependencies]
# Phase B additions:
rustc-hash = "2"
arrayvec = "0.7"
bon = "3"

[dev-dependencies]
trybuild = "1"
```

No feature gate — these dependencies are unconditional (the `monitor` module is gated on `tokio + flow`, which is also when these deps matter).

### 5.2 `Ctx<'a>` + extractors — `src/ctx/`

`src/ctx/mod.rs`:

```rust
//! Per-event context passed to handlers.
//!
//! `Ctx` lives on the dispatch stack — never heap-allocated.
//! Handlers borrow from it via the `FromCtx` trait; the borrow
//! lifetime is exactly the dispatch call.

use flowscope::Timestamp;

use crate::protocol::FlowKey;

pub mod from_ctx;
pub mod extractors;

pub use from_ctx::{CounterRegistry, FromCtx, StateMap};
pub use extractors::{Counter, Now, Sink, State};

/// Tag for which capture source this event came from.
/// `SourceIdx(0)` for single-interface monitors; multi-interface
/// (Phase E) increments per registered iface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceIdx(pub u8);

/// Runtime context passed to every handler invocation.
///
/// Field accesses are gated through the `FromCtx` extractor trait
/// in normal code; the public field on `flow` is convenience for
/// closures that just want `ctx.flow`.
pub struct Ctx<'a> {
    /// The flow key for the current event, if any.
    pub flow: Option<&'a FlowKey>,

    /// Timestamp of the current event. `Copy` — extract via `Now`.
    pub ts: Timestamp,

    /// Source-interface index.
    pub source: SourceIdx,

    /// Per-monitor user state, keyed by `TypeId`.
    pub(crate) state_map: &'a mut StateMap,

    /// The anomaly sink. Phase C fills in the trait body; Phase B
    /// uses a stub so the dispatcher compiles.
    pub(crate) sink: &'a mut dyn crate::anomaly::sink::AnomalySink,

    /// Per-monitor counter storage.
    pub(crate) counters: &'a mut CounterRegistry,
}
```

`src/ctx/from_ctx.rs`:

```rust
use std::any::{Any, TypeId};
use std::collections::HashMap;

use rustc_hash::FxHashMap;

use crate::correlate::TimeBucketedCounter;
use crate::ctx::Ctx;

/// Extract a typed view from `&mut Ctx<'_>`.
///
/// `Target<'a>` is the lifetime-bound view returned. For `State<T>`
/// this is `&'a mut T`; for `Sink<()>` it's `&'a mut dyn AnomalySink`;
/// for `Now` it's `Timestamp` (by value).
pub trait FromCtx {
    type Target<'a>;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Self::Target<'a>;
}

/// Type-keyed state map. One slot per `T: Default` registered via
/// `MonitorBuilder::state::<T>()`. Lazy-initializes on first access.
#[derive(Default)]
pub struct StateMap {
    by_type: FxHashMap<TypeId, Box<dyn Any + Send>>,
}

impl StateMap {
    pub fn get_or_init_mut<T: Default + Send + 'static>(&mut self) -> &mut T {
        let id = TypeId::of::<T>();
        self.by_type
            .entry(id)
            .or_insert_with(|| Box::<T>::default())
            .downcast_mut::<T>()
            .expect("StateMap invariant: TypeId keys to its own T")
    }
}

/// Type-keyed counter registry. Each `K: Eq + Hash` registered via
/// `MonitorBuilder::counter::<K>(window, bucket)` gets one preallocated
/// `TimeBucketedCounter<K>`.
#[derive(Default)]
pub struct CounterRegistry {
    by_type: FxHashMap<TypeId, Box<dyn Any + Send>>,
}

impl CounterRegistry {
    pub(crate) fn register<K>(&mut self, counter: TimeBucketedCounter<K>)
    where K: Eq + std::hash::Hash + Send + 'static {
        let id = TypeId::of::<K>();
        self.by_type.insert(id, Box::new(counter));
    }

    pub fn get_mut<K>(&mut self) -> &mut TimeBucketedCounter<K>
    where K: Eq + std::hash::Hash + Send + 'static {
        let id = TypeId::of::<K>();
        self.by_type
            .get_mut(&id)
            .expect("counter::<K> not registered — call .counter::<K>(...) on the builder")
            .downcast_mut::<TimeBucketedCounter<K>>()
            .expect("CounterRegistry invariant: TypeId keys to its own counter")
    }
}
```

`src/ctx/extractors.rs`:

```rust
use std::marker::PhantomData;

use flowscope::Timestamp;

use crate::anomaly::sink::AnomalySink;
use crate::correlate::TimeBucketedCounter;
use crate::ctx::{Ctx, FromCtx};

/// Per-monitor shared user state. Lazy-initialized via `Default`.
pub struct State<T>(PhantomData<fn() -> T>);

impl<T: Default + Send + 'static> FromCtx for State<T> {
    type Target<'a> = &'a mut T;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut T {
        ctx.state_map.get_or_init_mut::<T>()
    }
}

/// The anomaly sink. The `A` phantom is reserved for type-tagged
/// sinks in a future revision (`Sink<MetricsSink>`); today the
/// extractor returns `&mut dyn AnomalySink` regardless of `A`.
pub struct Sink<A = ()>(PhantomData<fn() -> A>);

impl<A: 'static> FromCtx for Sink<A> {
    type Target<'a> = &'a mut dyn AnomalySink;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut dyn AnomalySink {
        ctx.sink
    }
}

/// Current event timestamp (`Copy`).
pub struct Now;

impl FromCtx for Now {
    type Target<'a> = Timestamp;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Timestamp {
        ctx.ts
    }
}

/// Per-key sliding-window counter. Must be registered via
/// `MonitorBuilder::counter::<K>(...)` before any handler uses it.
pub struct Counter<K>(PhantomData<fn() -> K>);

impl<K: Eq + std::hash::Hash + Send + 'static> FromCtx for Counter<K> {
    type Target<'a> = &'a mut TimeBucketedCounter<K>;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut TimeBucketedCounter<K> {
        ctx.counters.get_mut::<K>()
    }
}
```

### 5.3 `Handler<E, M>` trait + blanket impl macro — `src/monitor/handler.rs`

```rust
//! Handler trait + blanket impls. Phase B ships sync handlers only.
//! Async handlers land in Phase D as a separate `AsyncHandler` trait.

use crate::ctx::{Ctx, FromCtx};
use crate::error::Result;
use crate::protocol::event_typed::Event;

/// A handler is "something that can be called with `&E::Payload`
/// + extractors, producing a `Result<()>`".
///
/// The `M` type parameter is the **axum coherence marker** — it
/// lets one closure type `F` implement `Handler<E, (P1,)>` and
/// `Handler<E, (P1, P2)>` without overlap errors. Users never
/// name `M`.
pub trait Handler<E: Event, M>: Send + Sync + 'static {
    fn call(&self, payload: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()>;
}

// Macro-generated blanket impls for N = 0..=8 extractor parameters.
macro_rules! impl_handler {
    // 0 extractors:
    () => {
        impl<E, F> Handler<E, ()> for F
        where
            E: Event,
            F: Fn(&E::Payload) -> Result<()> + Send + Sync + 'static,
        {
            #[inline]
            fn call(&self, p: &E::Payload, _ctx: &mut Ctx<'_>) -> Result<()> {
                self(p)
            }
        }
    };

    // N extractors:
    ( $($P:ident),+ ) => {
        impl<E, F, $($P),+> Handler<E, ($($P,)+)> for F
        where
            E: Event,
            F: for<'a> Fn(
                &'a E::Payload,
                $(<$P as FromCtx>::Target<'a>),+
            ) -> Result<()> + Send + Sync + 'static,
            $($P: FromCtx + 'static),+
        {
            #[inline]
            fn call(&self, p: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()> {
                // Sequential extraction — Rust's borrow checker
                // tracks each `Target<'_>`'s lifetime separately.
                // For disjoint-field access, use `ctx.split_*`
                // helpers (Phase C); this default path serializes
                // extractor calls.
                $(
                    let $P = <$P as FromCtx>::from_ctx(ctx);
                )+
                self(p, $($P),+)
            }
        }
    };
}

impl_handler!();
impl_handler!(P1);
impl_handler!(P1, P2);
impl_handler!(P1, P2, P3);
impl_handler!(P1, P2, P3, P4);
impl_handler!(P1, P2, P3, P4, P5);
impl_handler!(P1, P2, P3, P4, P5, P6);
impl_handler!(P1, P2, P3, P4, P5, P6, P7);
impl_handler!(P1, P2, P3, P4, P5, P6, P7, P8);
```

**Critical:** the `for<'a> Fn(&'a E::Payload, <$P as FromCtx>::Target<'a>, ...) -> Result<()>` higher-rank bound is the axum-style coherence trick. Two-extractor closures and one-extractor closures live in distinct `M` slots, so there's no overlap.

### 5.4 `Dispatcher` + `HandlerRegistry` — `src/monitor/dispatcher.rs` + `src/monitor/registry.rs`

`src/monitor/dispatcher.rs`:

```rust
use std::any::{Any, TypeId};

use arrayvec::ArrayVec;

use crate::ctx::Ctx;
use crate::error::Result;

/// Type-erased boxed handler. The pointer-cast signature avoids
/// `dyn Any` for the payload at dispatch (one less indirection).
pub(crate) type BoxedHandler =
    Box<dyn FnMut(*const (), &mut Ctx<'_>) -> Result<()> + Send>;

pub(crate) struct HandlerSlot {
    pub handler: BoxedHandler,
}

/// The build-time-finalized dispatcher.
pub struct Dispatcher {
    /// `TypeId::of::<E::Payload>()` → u8 slot index. ≤16 entries.
    slot_by_type: ArrayVec<(TypeId, u8), 16>,
    /// Slot table — handlers grouped by payload type.
    slots: Box<[Vec<HandlerSlot>]>,
}

impl Dispatcher {
    #[inline]
    pub fn dispatch<P: 'static>(&mut self, payload: &P, ctx: &mut Ctx<'_>) -> Result<()> {
        let Some(slot_idx) = self
            .slot_by_type
            .iter()
            .find(|(t, _)| *t == TypeId::of::<P>())
            .map(|(_, s)| *s as usize)
        else { return Ok(()) };

        let ptr = payload as *const P as *const ();
        for slot in &mut self.slots[slot_idx] {
            (slot.handler)(ptr, ctx)?;
        }
        Ok(())
    }
}

impl Dispatcher {
    pub(crate) fn new(
        slot_by_type: ArrayVec<(TypeId, u8), 16>,
        slots: Box<[Vec<HandlerSlot>]>,
    ) -> Self {
        Self { slot_by_type, slots }
    }
}
```

`src/monitor/registry.rs`:

```rust
use std::any::TypeId;

use arrayvec::ArrayVec;
use rustc_hash::FxHashMap;

use crate::ctx::Ctx;
use crate::error::{BuildError, Result};
use crate::monitor::dispatcher::{BoxedHandler, Dispatcher, HandlerSlot};
use crate::monitor::handler::Handler;
use crate::protocol::event_typed::Event;

#[derive(Default)]
pub struct HandlerRegistry {
    by_type: FxHashMap<TypeId, Vec<BoxedHandler>>,
}

impl HandlerRegistry {
    pub fn register<E: Event, H: Handler<E, M>, M: 'static>(&mut self, handler: H) {
        let boxed: BoxedHandler = Box::new(move |ptr, ctx| {
            // SAFETY: dispatcher only calls this handler for slots
            // keyed by TypeId::of::<E::Payload>(); registration
            // invariant guarantees `ptr` is a `*const E::Payload`.
            let typed: &E::Payload = unsafe { &*(ptr as *const E::Payload) };
            handler.call(typed, ctx)
        });
        self.by_type
            .entry(TypeId::of::<E::Payload>())
            .or_default()
            .push(boxed);
    }

    pub fn into_dispatcher(self) -> Result<Dispatcher, BuildError> {
        if self.by_type.len() > 16 {
            return Err(BuildError::TooManyEventTypes {
                limit: 16,
                actual: self.by_type.len(),
            });
        }
        let mut slot_by_type = ArrayVec::new();
        let mut slots = Vec::with_capacity(self.by_type.len());
        for (i, (type_id, handlers)) in self.by_type.into_iter().enumerate() {
            slot_by_type.push((type_id, i as u8));
            slots.push(
                handlers.into_iter().map(|h| HandlerSlot { handler: h }).collect(),
            );
        }
        Ok(Dispatcher::new(slot_by_type, slots.into_boxed_slice()))
    }
}
```

### 5.5 `TypedProtocolSlot<P>` + `ProtocolSlot` trait

In `src/monitor/registry.rs`:

```rust
use flowscope::driver::{SlotHandle, SlotMessage};

use crate::protocol::Protocol;

/// Drains a flowscope `SlotHandle` and dispatches each typed
/// message through the netring dispatcher.
pub(crate) trait ProtocolSlot {
    fn drain_and_dispatch(
        &mut self,
        dispatcher: &mut Dispatcher,
        ctx: &mut Ctx<'_>,
    ) -> Result<()>;
}

pub(crate) struct TypedProtocolSlot<P: Protocol> {
    pub(crate) handle: SlotHandle<P::Message, crate::protocol::FlowKey>,
    pub(crate) scratch: Vec<SlotMessage<P::Message, crate::protocol::FlowKey>>,
}

impl<P: Protocol> ProtocolSlot for TypedProtocolSlot<P> {
    fn drain_and_dispatch(
        &mut self,
        dispatcher: &mut Dispatcher,
        ctx: &mut Ctx<'_>,
    ) -> Result<()> {
        self.scratch.clear();
        let n = self.handle.drain(&mut self.scratch);
        if n == 0 { return Ok(()) }

        for slot_msg in self.scratch.drain(..) {
            // Each typed message dispatches against TypeId::of::<P::Message>().
            // ctx.flow / ctx.ts get the per-message override during this call.
            let saved_flow = ctx.flow;
            let saved_ts = ctx.ts;
            ctx.flow = Some(&slot_msg.key);
            ctx.ts = slot_msg.ts;
            let res = dispatcher.dispatch::<P::Message>(&slot_msg.message, ctx);
            ctx.flow = saved_flow;
            ctx.ts = saved_ts;
            res?;
        }
        Ok(())
    }
}
```

### 5.6 `Monitor` + `MonitorBuilder` — `src/monitor/mod.rs`

```rust
//! Top-level Monitor builder + Monitor struct + run modes.

use std::time::Duration;

use flowscope::driver::Driver;
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::correlate::TimeBucketedCounter;
use crate::ctx::{Ctx, CounterRegistry, SourceIdx, StateMap};
use crate::error::{BuildError, Result};
use crate::monitor::dispatcher::Dispatcher;
use crate::monitor::handler::Handler;
use crate::monitor::registry::{HandlerRegistry, ProtocolSlot, TypedProtocolSlot};
use crate::protocol::event_typed::{Event, Tick};
use crate::protocol::{Dispatch, ParserKind, Protocol};

pub mod dispatcher;
pub mod handler;
pub mod registry;
pub mod run;
pub mod tick;

/// The high-level Monitor. Produced by `Monitor::builder().build()`.
pub struct Monitor {
    pub(crate) interfaces: Vec<String>,
    pub(crate) driver: Driver<FiveTuple>,
    pub(crate) dispatcher: Dispatcher,
    pub(crate) protocol_slots: Vec<Box<dyn ProtocolSlot>>,
    pub(crate) state_map: StateMap,
    pub(crate) counters: CounterRegistry,
    pub(crate) sink: Box<dyn crate::anomaly::sink::AnomalySink>,
    pub(crate) tick_handlers: Vec<tick::TickRegistration>,
}

impl Monitor {
    pub fn builder() -> MonitorBuilder {
        MonitorBuilder::default()
    }
}

/// Builder for [`Monitor`]. Constructed via [`Monitor::builder`].
#[derive(Default)]
pub struct MonitorBuilder {
    interfaces: Vec<String>,
    driver_builder: Option<flowscope::driver::DriverBuilder<FiveTuple>>,
    protocol_slots: Vec<Box<dyn ProtocolSlot>>,
    handlers: HandlerRegistry,
    state_map: StateMap,
    counters: CounterRegistry,
    sink: Option<Box<dyn crate::anomaly::sink::AnomalySink>>,
    tick_handlers: Vec<tick::TickRegistration>,
}

impl MonitorBuilder {
    /// Set the network interface(s). Single-iface in Phase B;
    /// multi-iface in Phase E.
    pub fn interfaces<I, S>(mut self, ifaces: I) -> Self
    where I: IntoIterator<Item = S>, S: Into<String>
    {
        self.interfaces = ifaces.into_iter().map(Into::into).collect();
        self
    }

    /// Single-interface convenience.
    pub fn interface(self, iface: impl Into<String>) -> Self {
        self.interfaces([iface])
    }

    /// Register a protocol. Routes packets through its parser per
    /// `P::dispatch()`.
    pub fn protocol<P: Protocol>(mut self) -> Self {
        let builder = self
            .driver_builder
            .get_or_insert_with(|| Driver::builder(FiveTuple::bidirectional()));

        match (P::dispatch(), P::parser()) {
            // Lifecycle-only markers — no parser slot.
            (Dispatch::AllTcp, Err(_)) | (Dispatch::AllUdp, Err(_)) => { /* nothing */ }
            (Dispatch::Tcp(ports), Ok(ParserKind::Session(parser))) => {
                let handle = builder.session_on_ports(*parser, ports);
                self.protocol_slots
                    .push(Box::new(TypedProtocolSlot::<P> { handle, scratch: Vec::new() }));
            }
            (Dispatch::Udp(ports), Ok(ParserKind::Datagram(parser))) => {
                let handle = builder.datagram_on_ports(*parser, ports);
                self.protocol_slots
                    .push(Box::new(TypedProtocolSlot::<P> { handle, scratch: Vec::new() }));
            }
            (Dispatch::Icmp, Ok(ParserKind::Datagram(parser))) => {
                let handle = builder.datagram_broadcast(*parser);
                self.protocol_slots
                    .push(Box::new(TypedProtocolSlot::<P> { handle, scratch: Vec::new() }));
            }
            (Dispatch::Signature(sig), Ok(ParserKind::Session(parser))) => {
                let handle = builder.session_heuristic(*parser, sig);
                self.protocol_slots
                    .push(Box::new(TypedProtocolSlot::<P> { handle, scratch: Vec::new() }));
            }
            (d, k) => {
                panic!("Protocol::dispatch + Protocol::parser shape mismatch \
                       for {}: {:?} / {:?}", P::NAME, d, k.is_ok());
            }
        }
        self
    }

    /// Register a sync handler for event type `E`.
    pub fn on<E, H, M>(mut self, handler: H) -> Self
    where E: Event, H: Handler<E, M>, M: 'static
    {
        self.handlers.register::<E, H, M>(handler);
        self
    }

    /// Reserve a `T: Default` slot in the StateMap. Optional —
    /// `State<T>` extractor lazy-creates on first access, but
    /// pre-registering surfaces typos at build time.
    pub fn state<T: Default + Send + 'static>(mut self) -> Self {
        let _ = self.state_map.get_or_init_mut::<T>();
        self
    }

    /// Register a `Counter<K>` with explicit sliding-window + bucket params.
    pub fn counter<K>(mut self, window: Duration, bucket: Duration) -> Self
    where K: Eq + std::hash::Hash + Send + 'static
    {
        self.counters.register::<K>(TimeBucketedCounter::new(window, bucket));
        self
    }

    /// Replace the default `NoopSink` with a user-supplied sink.
    /// Phase D adds `.layer(...)` for middleware that wraps the
    /// sink chain.
    pub fn sink<S: crate::anomaly::sink::AnomalySink + 'static>(mut self, sink: S) -> Self {
        self.sink = Some(Box::new(sink));
        self
    }

    /// Periodic tick handler. Fires every `period` from the run loop.
    pub fn tick<H, M>(mut self, period: Duration, handler: H) -> Self
    where H: Handler<Tick, M>, M: 'static
    {
        self.tick_handlers.push(tick::TickRegistration::new(period, handler));
        self
    }

    /// Build. Single-interface only in Phase B (multi-iface in Phase E).
    pub fn build(self) -> Result<Monitor, BuildError> {
        if self.interfaces.is_empty() {
            return Err(BuildError::NoInterface);
        }
        if self.interfaces.len() > 1 {
            return Err(BuildError::MultiInterfaceNotYetSupported);
        }
        let driver = self
            .driver_builder
            .unwrap_or_else(|| Driver::builder(FiveTuple::bidirectional()))
            .build();
        let dispatcher = self.handlers.into_dispatcher()?;
        let sink = self
            .sink
            .unwrap_or_else(|| Box::new(crate::anomaly::sink::NoopSink));
        Ok(Monitor {
            interfaces: self.interfaces,
            driver,
            dispatcher,
            protocol_slots: self.protocol_slots,
            state_map: self.state_map,
            counters: self.counters,
            sink,
            tick_handlers: self.tick_handlers,
        })
    }
}

impl Monitor {
    /// Run until `deadline`.
    pub async fn run_until(self, deadline: std::time::Instant) -> Result<()> {
        run::run_loop(self, run::StopCondition::Deadline(deadline)).await
    }

    /// Run for `duration`.
    pub async fn run_for(self, duration: Duration) -> Result<()> {
        self.run_until(std::time::Instant::now() + duration).await
    }

    /// Run until SIGINT / SIGTERM.
    pub async fn run_until_signal(self) -> Result<()> {
        run::run_loop(self, run::StopCondition::Signal).await
    }
}
```

### 5.7 The run loop — `src/monitor/run.rs`

```rust
use std::time::Instant;

use flowscope::driver::Event as FsEvent;
use flowscope::L4Proto;
use futures::StreamExt;

use crate::ctx::{Ctx, SourceIdx};
use crate::error::Result;
use crate::monitor::Monitor;
use crate::protocol::builtin::{Icmp, Tcp, Udp};
use crate::protocol::event_typed::{FlowEnded, FlowEstablished, FlowStarted};

pub(crate) enum StopCondition {
    Deadline(Instant),
    Signal,
}

pub(crate) async fn run_loop(mut monitor: Monitor, stop: StopCondition) -> Result<()> {
    let iface = monitor.interfaces[0].clone();
    let cap = crate::AsyncCapture::open(&iface)?;
    let mut packet_stream = cap.into_stream();

    let mut events: Vec<FsEvent<crate::protocol::FlowKey>> = Vec::with_capacity(64);

    let stop_at = match stop {
        StopCondition::Deadline(t) => Some(t),
        StopCondition::Signal => {
            // Phase B keeps signal handling simple — TODO in E
            None
        }
    };

    while let Some(packet) = packet_stream.next().await {
        if let Some(t) = stop_at { if Instant::now() >= t { break } }

        let packet = packet?;
        let view = flowscope::PacketView::new(&packet.data, packet.timestamp);

        // (1) Lifecycle events from the central flow tracker.
        events.clear();
        monitor.driver.track_into(view, &mut events);

        for evt in events.drain(..) {
            dispatch_lifecycle(&mut monitor, evt)?;
        }

        // (2) Typed messages from each registered slot.
        for slot in &mut monitor.protocol_slots {
            let mut ctx = Ctx {
                flow: None,
                ts: flowscope::Timestamp::default(),
                source: SourceIdx(0),
                state_map: &mut monitor.state_map,
                sink: monitor.sink.as_mut(),
                counters: &mut monitor.counters,
            };
            slot.drain_and_dispatch(&mut monitor.dispatcher, &mut ctx)?;
        }
    }
    Ok(())
}

fn dispatch_lifecycle(
    monitor: &mut Monitor,
    evt: FsEvent<crate::protocol::FlowKey>,
) -> Result<()> {
    let mut ctx = Ctx {
        flow: None,
        ts: flowscope::Timestamp::default(),
        source: SourceIdx(0),
        state_map: &mut monitor.state_map,
        sink: monitor.sink.as_mut(),
        counters: &mut monitor.counters,
    };

    match evt {
        FsEvent::FlowStarted { key, ts, l4 } => {
            ctx.flow = Some(&key);
            ctx.ts = ts;
            match l4 {
                Some(L4Proto::Tcp) => {
                    let p = FlowStarted::<Tcp>::new(key.clone(), l4, ts);
                    monitor.dispatcher.dispatch::<FlowStarted<Tcp>>(&p, &mut ctx)?;
                }
                Some(L4Proto::Udp) => {
                    let p = FlowStarted::<Udp>::new(key.clone(), l4, ts);
                    monitor.dispatcher.dispatch::<FlowStarted<Udp>>(&p, &mut ctx)?;
                }
                Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => {
                    let p = FlowStarted::<Icmp>::new(key.clone(), l4, ts);
                    monitor.dispatcher.dispatch::<FlowStarted<Icmp>>(&p, &mut ctx)?;
                }
                _ => {}
            }
        }
        FsEvent::FlowEnded { key, reason, stats, l4, ts, .. } => {
            ctx.flow = Some(&key);
            ctx.ts = ts;
            match l4 {
                Some(L4Proto::Tcp) => {
                    let p = FlowEnded::<Tcp>::new(key.clone(), reason, stats, l4, ts);
                    monitor.dispatcher.dispatch::<FlowEnded<Tcp>>(&p, &mut ctx)?;
                }
                Some(L4Proto::Udp) => {
                    let p = FlowEnded::<Udp>::new(key.clone(), reason, stats, l4, ts);
                    monitor.dispatcher.dispatch::<FlowEnded<Udp>>(&p, &mut ctx)?;
                }
                Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => {
                    let p = FlowEnded::<Icmp>::new(key.clone(), reason, stats, l4, ts);
                    monitor.dispatcher.dispatch::<FlowEnded<Icmp>>(&p, &mut ctx)?;
                }
                _ => {}
            }
        }
        FsEvent::FlowEstablished { key, ts, l4 } => {
            ctx.flow = Some(&key);
            ctx.ts = ts;
            if matches!(l4, Some(L4Proto::Tcp)) {
                let p = FlowEstablished::<Tcp>::new(key.clone(), ts);
                monitor.dispatcher.dispatch::<FlowEstablished<Tcp>>(&p, &mut ctx)?;
            }
        }
        FsEvent::FlowAnomaly { key, kind, ts } => {
            use crate::protocol::event_typed::AnyFlowAnomaly;
            let p = AnyFlowAnomaly { key: Some(key.clone()), kind, ts };
            monitor.dispatcher.dispatch::<AnyFlowAnomaly>(&p, &mut ctx)?;
        }
        FsEvent::TrackerAnomaly { kind, ts } => {
            use crate::protocol::event_typed::AnyFlowAnomaly;
            let p = AnyFlowAnomaly { key: None, kind, ts };
            monitor.dispatcher.dispatch::<AnyFlowAnomaly>(&p, &mut ctx)?;
        }
        // FlowPacket / FlowTick / ParserClosed — Phase B skips
        // these; Phase E or F may add typed events for them.
        _ => {}
    }
    Ok(())
}
```

### 5.8 Tick handler plumbing — `src/monitor/tick.rs`

```rust
use std::time::Duration;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::monitor::handler::Handler;
use crate::protocol::event_typed::Tick;

pub(crate) struct TickRegistration {
    pub period: Duration,
    pub handler: Box<dyn FnMut(&Tick, &mut Ctx<'_>) -> Result<()> + Send>,
}

impl TickRegistration {
    pub(crate) fn new<H, M>(period: Duration, handler: H) -> Self
    where H: Handler<Tick, M>, M: 'static
    {
        Self {
            period,
            handler: Box::new(move |tick, ctx| handler.call(tick, ctx)),
        }
    }
}
```

Phase B wires the registration but the periodic firing is a no-op (no `tokio::time::interval` race against the packet stream). Phase F's per-CPU sharding adds the real tick scheduling.

### 5.9 `error.rs` additions

```rust
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("at least one interface required (call .interface(...) or .interfaces([...]))")]
    NoInterface,
    #[error("multi-interface monitors land in Phase E")]
    MultiInterfaceNotYetSupported,
    #[error("too many event types registered: limit {limit}, found {actual}")]
    TooManyEventTypes { limit: usize, actual: usize },
    #[error("dispatch shape mismatch in Protocol impl: {0}")]
    ProtocolDispatchMismatch(String),
}
```

### 5.10 Stub `AnomalySink` — `src/anomaly/sink.rs`

The full `AnomalySink` + `AnomalyWriter` lands in Phase C. Phase B needs a minimum stub for the dispatcher to compile:

```rust
//! Anomaly sink. Phase B ships a stub; Phase C fills in the API.

pub trait AnomalySink: Send {
    // Phase C adds methods. For Phase B the trait is empty —
    // it exists so Ctx::sink: &mut dyn AnomalySink type-checks.
}

/// No-op sink — used as the default when no `.sink(...)` is set.
pub struct NoopSink;
impl AnomalySink for NoopSink {}
```

This is a *forward declaration* — Phase C adds `begin()` + `AnomalyWriter`. The Phase B `Sink<A>` extractor compiles because it returns `&mut dyn AnomalySink`; no methods are called on it yet by user code in this phase.

## 6. Tests

### Unit tests (per module)

- `src/monitor/dispatcher.rs` inline: dispatch routes a payload to the right slot; slot with no handlers is a no-op; >16 event types produces `BuildError`.
- `src/monitor/registry.rs` inline: register two handlers for the same event; both fire in registration order.
- `src/ctx/from_ctx.rs` inline: `StateMap::get_or_init_mut` lazy-creates; `CounterRegistry::get_mut` panics on missing.

### Integration tests

`tests/handler_blanket.rs`:

```rust
//! Verify that closures with 0..8 extractor params satisfy
//! `Handler<E, M>` and can be registered + dispatched.

use std::time::Duration;
use netring::ctx::{Now, State};
use netring::monitor::Monitor;
use netring::protocol::builtin::{Http, Tcp};
use netring::protocol::event_typed::FlowStarted;

#[derive(Default)]
struct MyState { counter: u64 }

#[test]
fn zero_extractor_compiles() {
    let _m = Monitor::builder()
        .interface("lo")
        .on::<Http>(|_msg| Ok(()))
        .build();
}

#[test]
fn one_extractor_state_compiles() {
    let _m = Monitor::builder()
        .interface("lo")
        .state::<MyState>()
        .on::<FlowStarted<Tcp>>(|_evt, state: State<MyState>| {
            state.counter += 1;
            Ok(())
        })
        .build();
}

#[test]
fn two_extractor_state_now() {
    let _m = Monitor::builder()
        .interface("lo")
        .state::<MyState>()
        .on::<FlowStarted<Tcp>>(|_evt, state: State<MyState>, ts: Now| {
            state.counter += 1;
            let _ = ts.0;
            Ok(())
        })
        .build();
}
```

`tests/monitor_e2e.rs`:

```rust
//! End-to-end synthetic test — drive events through a Monitor
//! without a real capture.

// Phase B's run loop drives off AsyncCapture; this E2E test
// will need a Phase F or G PcapSource adapter to ship.
// For Phase B we test dispatcher correctness directly via
// `tests/dispatcher_typeid.rs` instead.
```

`tests/dispatcher_typeid.rs`:

```rust
//! Verify the dispatcher routes by TypeId correctly without a
//! real capture.

use netring::ctx::{Ctx, CounterRegistry, SourceIdx, StateMap};
use netring::monitor::dispatcher::Dispatcher;
use netring::monitor::registry::HandlerRegistry;
use netring::protocol::builtin::{Tcp, Udp};
use netring::protocol::event_typed::FlowStarted;
use std::sync::Mutex;

#[test]
fn typed_dispatch_routes_by_protocol_marker() {
    let tcp_count = std::sync::Arc::new(Mutex::new(0u32));
    let udp_count = std::sync::Arc::new(Mutex::new(0u32));
    let t = tcp_count.clone(); let u = udp_count.clone();

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
        *t.lock().unwrap() += 1; Ok(())
    });
    reg.register::<FlowStarted<Udp>, _, _>(move |_evt: &FlowStarted<Udp>| {
        *u.lock().unwrap() += 1; Ok(())
    });
    let mut disp = reg.into_dispatcher().unwrap();

    // Synthesize a FlowStarted<Tcp> and dispatch:
    let mut sink = netring::anomaly::sink::NoopSink;
    let mut state = StateMap::default();
    let mut counters = CounterRegistry::default();
    let mut ctx = Ctx {
        flow: None, ts: flowscope::Timestamp::default(),
        source: SourceIdx(0),
        state_map: &mut state, sink: &mut sink,
        counters: &mut counters,
    };

    let key = flowscope::extract::FiveTupleKey::default();
    let p = FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp),
        flowscope::Timestamp::default());
    disp.dispatch::<FlowStarted<Tcp>>(&p, &mut ctx).unwrap();

    assert_eq!(*tcp_count.lock().unwrap(), 1);
    assert_eq!(*udp_count.lock().unwrap(), 0);
}
```

### `trybuild` compile-fail tests

`tests/ui/borrow_conflict.rs`:

```rust
//! Two `&mut State<Same>` extractors should fail to compile due
//! to conflicting borrows. Phase B accepts this as expected
//! behavior; Phase C's split_* helpers explicitly cover the
//! case where the user wants disjoint access.

use netring::ctx::{Ctx, State};
use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

#[derive(Default)] struct MyState;

fn main() {
    let _m = Monitor::builder()
        .interface("lo")
        .state::<MyState>()
        .on::<FlowStarted<Tcp>>(
            |_evt, _a: State<MyState>, _b: State<MyState>| Ok(())
        )
        .build();
}
```

Expected compile failure message contains "cannot borrow `*ctx` as mutable more than once". `trybuild` golden-file tested.

`tests/handler_blanket.rs` runs the trybuild harness:

```rust
#[test]
fn compile_fail_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/borrow_conflict.rs");
}
```

## 7. Acceptance criteria

- [ ] `cargo build` clean.
- [ ] `cargo nextest run` — all existing tests + new tests pass (~310+ tests).
- [ ] `cargo +stable clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] `cargo test --doc` passes.
- [ ] `trybuild` compile-fail tests run + match golden files.
- [ ] A minimal `Monitor` example compiles end-to-end:
  ```rust
  Monitor::builder()
      .interface("lo")
      .protocol::<Http>()
      .on::<Http>(|_msg| Ok(()))
      .build()?
      .run_for(Duration::from_secs(1))
      .await?;
  ```
- [ ] The Phase A `ProtocolMonitorBuilder` user API still works (Phase G deletes it).
- [ ] No regression in any existing detector example — they continue to build (they use the *old* API).

## 8. Risks + mitigations

1. **`for<'a>` HRTB coherence might trip with multiple extractor arities.**
   axum solved this with the `M` phantom marker — same trick here. If a specific arity fails to compile, the standard fix is adjusting the macro to use distinct phantoms for distinct shapes. `tests/handler_blanket.rs` arity tests catch regressions.

2. **The unsafe pointer cast in `HandlerRegistry::register`.**
   Soundness invariant: registry only inserts handlers keyed by `TypeId::of::<E::Payload>()`, and dispatcher only invokes those handlers via `dispatch::<P>` where `TypeId::of::<P>() == TypeId::of::<E::Payload>()`. Documented in source. Add a `miri` job to `.github/workflows/ci.yml`.

3. **`SlotHandle` is `!Send`.**
   Same constraint as 0.19.0: `Monitor` is `!Send`. Users on `#[tokio::main(flavor = "current_thread")]` see no impact. Document in `Monitor` doc comment.

4. **`Protocol::parser()` lifecycle markers returning `Err`.**
   The `.protocol::<Tcp>()` builder method matches on the `Err` arm; an unrelated future protocol returning `Err` would silently skip parser registration. Mitigation: add a `BuildError::ProtocolDispatchMismatch` variant + emit it from the catch-all arm of the dispatch match.

5. **Periodic `Tick` events not actually firing.**
   Phase B accepts this — `TickRegistration` is recorded but no `tokio::time::interval` runs alongside the packet stream. Phase F's per-CPU sharding adds the real tick path. Document the gap in `MonitorBuilder::tick` rustdoc with "(Phase F)".

6. **`bon` v3 attribute spelling.**
   The redesign spec assumed `#[builder(field, default)]`. Verify at the start of Phase B. Fallback: hand-roll the typestate builder for `MonitorBuilder` — only ~6 stages, ~200 LoC. The methods we add via `impl MonitorBuilder` directly don't need `bon` at all.

## 9. Estimated effort + commit shape

**Total: 4–6 working days.** ~1,600 LoC new code + ~600 LoC tests.

**Commits (4):**

- `netring 0.20 (B.1): Ctx + FromCtx trait + StateMap + CounterRegistry` — ~300 LoC. Tests inline.
- `netring 0.20 (B.2): Handler trait + impl_handler! macro for 0..8 arities` — ~600 LoC after expansion. `tests/handler_blanket.rs` arity sweep.
- `netring 0.20 (B.3): Dispatcher + HandlerRegistry + TypedProtocolSlot wrapper` — ~500 LoC. `tests/dispatcher_typeid.rs`.
- `netring 0.20 (B.4): Monitor + MonitorBuilder + run loop + tick stub + AnomalySink stub` — ~600 LoC. `tests/monitor_e2e.rs` + minimal end-to-end compile test.

After B.4 the master branch should compile, test, lint clean; a minimal monitor example runs against a synthetic event source.

## 10. Cross-phase notes

- **Phase C** fills `AnomalySink` with the real `begin()` / `AnomalyWriter` API. The stub here is sufficient for B's dispatcher to compile.
- **Phase C** also adds `Ctx::split_state_sink::<T>()` + friends for the disjoint-borrow escape hatch.
- **Phase D** adds `AsyncHandler<E, M>` as a *separate* trait + `on_async::<E>()` builder method. Same blanket-impl machinery, different trait body.
- **Phase E** replaces `interfaces([single])` Build error with real multi-interface support via `AsyncMultiCapture`.
- **Phase F** adds the per-CPU sharded dispatcher; the single-shard `Dispatcher` defined here is wrapped one level deeper.
- **Phase G** deletes the existing `ProtocolMonitor` / `ProtocolMonitorBuilder` / `AnomalyMonitor` / `AnomalyRule` (the Phase A → 0.19.0 surface).

Ready to execute once Phase A is merged.
