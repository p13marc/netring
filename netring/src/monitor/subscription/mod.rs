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
//! evaluation and (Phase A2/A3) kernel pushdown. `on::<E>(h)` is reframed as
//! a subscription with an [`Always`](Predicate::Always) filter — the typed
//! builders are additive sugar, not a replacement.
//!
//! Phase A1 lands the AST + evaluator ([`predicate`]); the typed tier builders
//! and run-loop wiring land in the follow-up units.
//!
//! [`PacketView`]: flowscope::PacketView

pub mod builder;
pub(crate) mod kernel_filter;
pub mod packet;
pub mod predicate;

pub use builder::{
    FlowTier, HasHttpHost, HasQname, HasSni, PacketTier, SessionTier, SubscriptionBuilder, flow,
    packet, session,
};
pub use packet::{PacketHandler, PacketSubscription};
pub use predicate::{Atom, FieldSource, Glob, Predicate};
