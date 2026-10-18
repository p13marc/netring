//! 0.22 §5.1 — cross-shard state merging.
//!
//! Each shard runs an independent [`Monitor`](crate::monitor::Monitor)
//! on its own OS thread + `current_thread` tokio runtime. A merge
//! worker (one extra OS thread, **no** runtime) periodically asks each
//! shard for its copy of a state type `T`, folds the answers into a
//! persistent primary, and hands the primary to an observer.
//!
//! Channel shapes follow the threading model: requests reach each
//! shard's async run loop over a [`tokio::sync::mpsc`] (polled in the
//! run-loop `select!`); every shard answers over **one** shared
//! [`std::sync::mpsc`] channel, which the runtime-less worker blocks on
//! with a timeout (a stalled shard can't wedge the worker). The reply
//! channel outlives the probes (#216): a reply that arrives after its
//! probe gave up waiting is folded at the next pass instead of being
//! dropped with a per-probe channel. When its run ends, each shard pushes
//! one last reply per merged type, and the runner joins the shards before
//! it stops the worker, so the worker folds those final deltas too — the
//! last partial interval is no longer lost.
//!
//! Semantics: **take-and-reset** on the shard
//! ([`StateMap::take_reset`](crate::ctx::StateMap::take_reset): the slot
//! is handed over and re-seeded the way it was registered —
//! `T::default()` for `state::<T>()`, the factory for `state_init`), so
//! each reply carries the *delta* since the previous one; the primary
//! **accumulates** across intervals, i.e. it is the running grand total.

use std::any::{Any, TypeId};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Worker → shard: "take-and-reset your `T` slot and reply with it".
pub(crate) struct MergeRequest {
    pub(crate) type_id: TypeId,
}

/// Shard → worker: a taken delta. `value` is `None` when the shard had
/// no `T` slot.
pub(crate) struct MergeReply {
    pub(crate) type_id: TypeId,
    pub(crate) value: Option<Box<dyn Any + Send>>,
}

/// A shard's end of the merge channels. Injected by `ShardedRunner` via
/// `Monitor::set_merge_link`.
pub(crate) struct MergeLink {
    /// The worker's probes.
    pub(crate) requests: UnboundedReceiver<MergeRequest>,
    /// Where every reply goes (shared by all shards).
    pub(crate) replies: Sender<MergeReply>,
    /// Every merged type: pushed once more when the shard's run ends.
    pub(crate) types: Arc<[TypeId]>,
}

impl MergeLink {
    /// Answer `type_id`'s probe from `state`.
    pub(crate) fn reply(&self, state: &mut crate::ctx::StateMap, type_id: TypeId) {
        let value = state.take_reset(type_id);
        // The worker is gone only once the run is over.
        let _ = self.replies.send(MergeReply { type_id, value });
    }

    /// The shard's run ended: push what it accumulated since the last
    /// probe, for every merged type.
    pub(crate) fn push_final(&self, state: &mut crate::ctx::StateMap) {
        for &type_id in self.types.iter() {
            self.reply(state, type_id);
        }
    }
}

/// Type-erased fold: downcasts the primary (`&mut dyn Any`) + the
/// shard's taken value (`Box<dyn Any + Send>`) to `T` and applies the
/// user merge.
type FoldFn = Box<dyn FnMut(&mut dyn Any, Box<dyn Any + Send>) + Send>;
/// Type-erased observer over the primary.
type ObserveFn = Box<dyn Fn(&dyn Any) + Send>;

/// One registered merge: fold each shard's `T` into a persistent
/// primary, then observe the primary.
pub(crate) struct MergeSpec {
    type_id: TypeId,
    type_name: &'static str,
    period: Duration,
    /// `Box<T>`, accumulates across intervals (the grand total).
    primary: Box<dyn Any + Send>,
    /// Downcasts both sides to `T` and applies the user fold.
    fold: FoldFn,
    /// From `on_merge`: called with the primary after each interval.
    observe: Option<ObserveFn>,
}

impl MergeSpec {
    /// `merge_state` / `state_auto_merge` build this. `merge(&mut primary, shard_value)`.
    pub(crate) fn new<T, F>(period: Duration, mut merge: F) -> Self
    where
        T: Default + Send + 'static,
        F: FnMut(&mut T, T) + Send + 'static,
    {
        Self {
            type_id: TypeId::of::<T>(),
            type_name: std::any::type_name::<T>(),
            period,
            primary: Box::new(T::default()),
            fold: Box::new(move |primary, taken| {
                if let (Some(p), Ok(t)) = (primary.downcast_mut::<T>(), taken.downcast::<T>()) {
                    merge(p, *t);
                }
            }),
            observe: None,
        }
    }

    pub(crate) fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// `on_merge` attaches the observer to the matching `T` spec.
    pub(crate) fn set_observe<T, G>(&mut self, observe: G)
    where
        T: 'static,
        G: Fn(&T) + Send + 'static,
    {
        self.observe = Some(Box::new(move |primary| {
            if let Some(p) = primary.downcast_ref::<T>() {
                observe(p);
            }
        }));
    }

    fn observe(&self) {
        if let Some(obs) = &self.observe {
            obs(self.primary.as_ref());
        }
    }
}

/// Check the merges before a run: each needs a non-zero period (it would
/// re-probe the shards back to back), and each state type gets one merge
/// (#227) — a shard's delta is taken once, so it can feed one fold only.
pub(crate) fn validate(specs: &[MergeSpec]) -> crate::error::Result<()> {
    use crate::error::BuildError;
    if specs.iter().any(|m| m.period.is_zero()) {
        return Err(BuildError::ZeroPeriod {
            what: "merge_state / state_auto_merge",
        }
        .into());
    }
    for (i, spec) in specs.iter().enumerate() {
        if specs[..i].iter().any(|s| s.type_id == spec.type_id) {
            return Err(BuildError::DuplicateMergeState {
                type_name: spec.type_name,
            }
            .into());
        }
    }
    Ok(())
}

/// How long a probe waits for the shards' replies. Replies that come
/// later are folded at the next pass.
const REPLY_TIMEOUT: Duration = Duration::from_millis(500);

/// The merge worker thread body. Returns once `stop` is set, after
/// folding every reply still queued — the shards' final pushes included,
/// as long as they were joined first — and observing each primary once
/// more.
pub(crate) fn merge_worker(
    txs: Vec<UnboundedSender<MergeRequest>>,
    replies: Receiver<MergeReply>,
    specs: Vec<MergeSpec>,
    stop: Arc<AtomicBool>,
) {
    merge_worker_with(txs, replies, specs, stop, REPLY_TIMEOUT);
}

fn merge_worker_with(
    txs: Vec<UnboundedSender<MergeRequest>>,
    replies: Receiver<MergeReply>,
    mut specs: Vec<MergeSpec>,
    stop: Arc<AtomicBool>,
    reply_timeout: Duration,
) {
    if specs.is_empty() {
        return;
    }
    let mut next_fire: Vec<Instant> = specs
        .iter()
        .map(|s| crate::monitor::shard::deadline_after(s.period))
        .collect();

    while !stop.load(Ordering::Relaxed) {
        // Park until the soonest fire, in ≤50ms slices so `stop` stays
        // responsive — folding whatever replies come in meanwhile.
        let now = Instant::now();
        let soonest = next_fire
            .iter()
            .copied()
            .min()
            .unwrap_or_else(|| now + Duration::from_millis(50));
        let nap = soonest
            .saturating_duration_since(now)
            .min(Duration::from_millis(50));
        if !nap.is_zero() {
            match replies.recv_timeout(nap) {
                Ok(reply) => fold(&mut specs, reply),
                Err(RecvTimeoutError::Timeout) => {}
                // Every shard is gone: nothing more will arrive.
                Err(RecvTimeoutError::Disconnected) => break,
            }
            continue;
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let now = Instant::now();
        for i in 0..specs.len() {
            if now >= next_fire[i] {
                next_fire[i] = crate::monitor::shard::deadline_after(specs[i].period);
                probe(&mut specs, i, &txs, &replies, reply_timeout);
            }
        }
    }

    // The shards were joined before `stop` was set: their final pushes
    // are queued.
    while let Ok(reply) = replies.try_recv() {
        fold(&mut specs, reply);
    }
    for spec in &specs {
        spec.observe();
    }
}

/// Fold a reply into the spec of its type.
fn fold(specs: &mut [MergeSpec], reply: MergeReply) {
    let Some(value) = reply.value else { return };
    if let Some(spec) = specs.iter_mut().find(|s| s.type_id == reply.type_id) {
        (spec.fold)(spec.primary.as_mut(), value);
    }
}

/// Ask every shard for spec `i`'s type, fold the replies that come within
/// `timeout` (and any late ones of earlier probes), then observe.
fn probe(
    specs: &mut [MergeSpec],
    i: usize,
    txs: &[UnboundedSender<MergeRequest>],
    replies: &Receiver<MergeReply>,
    timeout: Duration,
) {
    let type_id = specs[i].type_id;
    let asked = txs
        .iter()
        .filter(|tx| tx.send(MergeRequest { type_id }).is_ok())
        .count();
    let deadline = Instant::now() + timeout;
    let mut answered = 0;
    while answered < asked {
        let left = deadline.saturating_duration_since(Instant::now());
        match replies.recv_timeout(left) {
            Ok(reply) => {
                if reply.type_id == type_id {
                    answered += 1;
                }
                fold(specs, reply);
            }
            Err(_) => break,
        }
    }
    specs[i].observe();
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;

    use super::*;
    use crate::ctx::StateMap;

    #[derive(Default)]
    struct Counter(u64);

    /// One fake shard on its own runtime, answering probes the way the run
    /// loop does: `link.reply` per probe, `link.push_final` when its run
    /// ends. `delay_first`: how long it sits on its first probe;
    /// `on_exit`: what it counts between its last probe and the end of its
    /// run.
    fn fake_shard(
        mut link: MergeLink,
        stop: Arc<AtomicBool>,
        start: u64,
        delay_first: Duration,
        on_exit: u64,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut state = StateMap::default();
                state.get_or_init_mut::<Counter>().0 = start;
                let mut first = true;
                while !stop.load(Ordering::Relaxed) {
                    tokio::select! {
                        req = link.requests.recv() => match req {
                            Some(req) => {
                                if first {
                                    first = false;
                                    tokio::time::sleep(delay_first).await;
                                }
                                link.reply(&mut state, req.type_id);
                            }
                            None => break,
                        },
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                    }
                }
                state.get_or_init_mut::<Counter>().0 += on_exit;
                link.push_final(&mut state);
            });
        })
    }

    /// A `Counter` sum whose observations are recorded.
    fn counting_spec(observed: &Arc<Mutex<Vec<u64>>>, period: Duration) -> MergeSpec {
        let mut spec =
            MergeSpec::new::<Counter, _>(period, |p: &mut Counter, t: Counter| p.0 += t.0);
        let observed = Arc::clone(observed);
        spec.set_observe::<Counter, _>(move |c: &Counter| observed.lock().unwrap().push(c.0));
        spec
    }

    /// `n` shards' links plus the worker's ends.
    fn links(
        n: usize,
    ) -> (
        Vec<MergeLink>,
        Vec<UnboundedSender<MergeRequest>>,
        Receiver<MergeReply>,
    ) {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let types: Arc<[TypeId]> = Arc::from([TypeId::of::<Counter>()]);
        let (links, txs) = (0..n)
            .map(|_| {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                let link = MergeLink {
                    requests: rx,
                    replies: reply_tx.clone(),
                    types: Arc::clone(&types),
                };
                (link, tx)
            })
            .unzip();
        (links, txs, reply_rx)
    }

    /// Run `shards` against a worker for `run`, then end them the way
    /// `ShardedRunner` does: shards first (joined), then the worker.
    fn run_merge(
        shards: Vec<(u64, Duration, u64)>,
        spec: MergeSpec,
        reply_timeout: Duration,
        run: Duration,
    ) {
        let (links, txs, replies) = links(shards.len());
        let stop = Arc::new(AtomicBool::new(false));
        let handles: Vec<_> = links
            .into_iter()
            .zip(shards)
            .map(|(link, (start, delay, on_exit))| {
                fake_shard(link, Arc::clone(&stop), start, delay, on_exit)
            })
            .collect();
        let worker_stop = Arc::new(AtomicBool::new(false));
        let w = Arc::clone(&worker_stop);
        let worker = std::thread::spawn(move || {
            merge_worker_with(txs, replies, vec![spec], w, reply_timeout)
        });
        std::thread::sleep(run);
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().unwrap();
        }
        worker_stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
    }

    /// End-to-end worker↔shard protocol without AF_PACKET: two fake
    /// shards each contribute `delta` once; the worker folds them into the
    /// grand total and observes it.
    #[test]
    fn worker_folds_each_shard_and_observes_grand_total() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let spec = counting_spec(&observed, Duration::from_millis(20));
        run_merge(
            vec![(5, Duration::ZERO, 0), (5, Duration::ZERO, 0)],
            spec,
            Duration::from_millis(500),
            Duration::from_millis(120),
        );
        let observed = observed.lock().unwrap();
        assert!(observed.len() >= 2, "{observed:?}");
        assert_eq!(*observed.last().unwrap(), 10);
    }

    /// #216: a reply that comes after its probe gave up waiting is folded
    /// at the next pass — it used to be sent into the probe's dropped
    /// channel, and the shard's delta was lost.
    #[test]
    fn late_reply_is_folded_next_pass() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let spec = counting_spec(&observed, Duration::from_millis(20));
        // The shard sits on its first probe for 5 reply timeouts.
        run_merge(
            vec![(5, Duration::from_millis(150), 0)],
            spec,
            Duration::from_millis(30),
            Duration::from_millis(500),
        );
        let observed = observed.lock().unwrap();
        // The first pass gave up (0); a later pass, still during the run,
        // folded the late delta.
        assert_eq!(observed.first(), Some(&0), "{observed:?}");
        let during_run = &observed[..observed.len() - 1];
        assert!(during_run.contains(&5), "{observed:?}");
        assert_eq!(*observed.last().unwrap(), 5);
    }

    /// #216: what a shard counts after its last probe — the run's last
    /// partial interval — reaches the grand total: the shard pushes it
    /// when its run ends, and the worker, stopped only after the shards
    /// were joined, folds it before its final observation.
    #[test]
    fn final_push_after_stop_is_folded() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        // A period longer than the run: no probe at all, only the final
        // pushes.
        let spec = counting_spec(&observed, Duration::from_secs(3600));
        run_merge(
            vec![(2, Duration::ZERO, 3), (0, Duration::ZERO, 4)],
            spec,
            Duration::from_millis(500),
            Duration::from_millis(50),
        );
        assert_eq!(*observed.lock().unwrap(), vec![9]);
    }

    /// #227: one merge per state type; a zero period is rejected too.
    #[test]
    fn validate_rejects_a_second_merge_for_a_type() {
        use crate::error::{BuildError, Error};
        let sum = || {
            MergeSpec::new::<Counter, _>(Duration::from_secs(1), |p: &mut Counter, t: Counter| {
                p.0 += t.0
            })
        };
        let max = || {
            MergeSpec::new::<Counter, _>(Duration::from_secs(5), |p: &mut Counter, t: Counter| {
                p.0 = p.0.max(t.0)
            })
        };
        let other = MergeSpec::new::<u64, _>(Duration::from_secs(1), |p: &mut u64, t: u64| *p += t);
        assert!(validate(&[sum(), other]).is_ok());
        match validate(&[sum(), max()]) {
            Err(Error::Build(BuildError::DuplicateMergeState { type_name })) => {
                assert!(type_name.ends_with("Counter"), "{type_name}")
            }
            other => panic!("{other:?}"),
        }
        let zero = MergeSpec::new::<u64, _>(Duration::ZERO, |p: &mut u64, t: u64| *p += t);
        assert!(matches!(
            validate(&[zero]),
            Err(Error::Build(BuildError::ZeroPeriod { .. }))
        ));
    }

    /// The worker exits promptly once every shard is gone, even without
    /// `stop` (all reply senders dropped), after a final observation.
    #[test]
    fn worker_exits_when_every_shard_is_gone() {
        let observed = Arc::new(AtomicU64::new(u64::MAX));
        let mut spec = MergeSpec::new::<Counter, _>(
            Duration::from_millis(20),
            |p: &mut Counter, t: Counter| p.0 += t.0,
        );
        let o = Arc::clone(&observed);
        spec.set_observe::<Counter, _>(move |c: &Counter| o.store(c.0, Ordering::Relaxed));
        let (links, txs, replies) = links(1);
        drop(links);
        let start = Instant::now();
        merge_worker_with(
            txs,
            replies,
            vec![spec],
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(30),
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(observed.load(Ordering::Relaxed), 0);
    }
}
