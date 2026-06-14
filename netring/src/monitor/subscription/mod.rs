//! Subscription engine (0.25 Phase A) — the typed, multi-tier front door.
//!
//! A **subscription** pairs a *tier* (which events it sees) with a *filter*
//! ([`Predicate`]) and a *handler*. Three tiers, each strongly typed so
//! invalid protocol/tier combinations don't compile (per the 0.22 roles):
//!
//! | constructor        | sees                                  | typed filters |
//! |--------------------|---------------------------------------|---------------|
//! | `packet()`         | every captured frame ([`PacketView`])  | proto / ports / host / net / vlan (kernel-pushable) |
//! | `flow::<P>()`      | `FlowStarted/Ended/Tick<P>`            | + byte / packet counts |
//! | `session::<P>()`   | `P::Message` (L7)                      | + sni / host / qname globs |
//!
//! The filter lowers to a single [`Predicate`] AST shared by userspace
//! evaluation and kernel pushdown (the OR-union of every consumer's interest is
//! compiled to cBPF and applied via `set_filter` — fail-open, starvation-free).
//! `on::<E>(h)` stays the ergonomic surface; tier subs are additive sugar that
//! deliver at the tier's natural point: packet = per-frame (pre-tracking),
//! flow = at `FlowEnded` with stats, session = when the L7 message parses.
//!
//! [`PacketView`]: flowscope::PacketView

pub mod builder;
pub mod flow;
pub(crate) mod kernel_filter;
pub mod packet;
pub mod predicate;
pub mod session;

pub use builder::{
    FlowTier, HasHttpHost, HasQname, HasSni, PacketTier, SessionTier, SubscriptionBuilder, flow,
    packet, session,
};
pub use flow::{FlowHandler, FlowSubscription};
pub use packet::{PacketHandler, PacketSubscription};
pub use predicate::{Atom, FieldSource, Glob, Predicate};
pub use session::{L7Fields, SessionHandler, SessionSubscription};

/// A built subscription that knows how to **install itself** onto a
/// [`MonitorBuilder`](crate::monitor::MonitorBuilder) (0.25 S3). Lets the one
/// [`subscribe`](crate::monitor::MonitorBuilder::subscribe) method accept any
/// tier — packet subs push onto the zero-copy drain; flow/session subs install
/// a predicate-gated handler on the existing typed dispatch.
pub trait Subscribable {
    /// Install this subscription, returning the updated builder.
    fn install(self, builder: crate::monitor::MonitorBuilder) -> crate::monitor::MonitorBuilder;
}

impl Subscribable for PacketSubscription {
    fn install(self, builder: crate::monitor::MonitorBuilder) -> crate::monitor::MonitorBuilder {
        builder.add_packet_sub(self)
    }
}

impl<P: crate::protocol::FlowProtocol> Subscribable for FlowSubscription<P> {
    fn install(self, builder: crate::monitor::MonitorBuilder) -> crate::monitor::MonitorBuilder {
        let pred = self.predicate;
        let user = self.handler;
        // Sugar: a predicate-gated handler on the flow's natural completion
        // event. The flow's traffic interest is recorded by `on_ctx` via
        // `FlowEnded<P>::traffic_class()` (a superset of the filter — safe).
        builder.on_ctx::<crate::protocol::event_typed::FlowEnded<P>>(
            move |evt: &crate::protocol::event_typed::FlowEnded<P>,
                  ctx: &mut crate::ctx::Ctx<'_>| {
                if pred.eval(&flow::FlowEndedFields { evt }) {
                    user(evt, ctx)
                } else {
                    Ok(())
                }
            },
        )
    }
}

impl<P> Subscribable for SessionSubscription<P>
where
    P: crate::protocol::MessageProtocol,
    P::Message: session::L7Fields,
{
    fn install(self, builder: crate::monitor::MonitorBuilder) -> crate::monitor::MonitorBuilder {
        let pred = self.predicate;
        let user = self.handler;
        // Sugar: a predicate-gated handler on the L7 message event. The 5-tuple
        // comes from `ctx.flow` (the message doesn't carry the key); L7 fields
        // come from the message via `L7Fields`. `on_ctx::<P>` records the
        // protocol's traffic interest (a superset of the filter — safe).
        builder.on_ctx::<P>(move |msg: &P::Message, ctx: &mut crate::ctx::Ctx<'_>| {
            let fields = session::SessionFields { key: ctx.flow, msg };
            if pred.eval(&fields) {
                user(msg, ctx)
            } else {
                Ok(())
            }
        })
    }
}
