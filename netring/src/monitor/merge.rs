//! 0.22 §5.1 — cross-shard state merging.
//!
//! Each shard runs an independent [`Monitor`](crate::monitor::Monitor)
//! on its own OS thread + `current_thread` tokio runtime. A merge
//! worker (one extra OS thread, **no** runtime) periodically probes
//! each shard for its copy of a state type `T`, folds them into a
//! persistent primary, and hands the primary to an observer.
//!
//! Channel shapes follow the threading model: the request is delivered
//! to the shard's async run loop over a [`tokio::sync::mpsc`] (polled
//! in the run-loop `select!`), while the reply comes back over a
//! [`std::sync::mpsc`] so the runtime-less worker can **block** on it
//! with a timeout (a stalled shard can't wedge the worker).
//!
//! Semantics: **take-and-reset** on the shard (the slot is removed; the
//! next `state_mut::<T>()` re-creates `T::default()`), so each interval
//! folds the *delta* since the last take; the primary **accumulates**
//! across intervals, i.e. it is the running grand total.

use std::any::{Any, TypeId};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::UnboundedSender;

/// Worker → shard: "remove your `T` slot and reply with it".
pub(crate) struct MergeRequest {
    pub(crate) type_id: TypeId,
    /// `std` channel — the worker has no tokio runtime, so it blocks on
    /// the reply (`recv_timeout`).
    pub(crate) reply: std::sync::mpsc::Sender<Option<Box<dyn Any + Send>>>,
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
}

/// The merge worker thread body. Returns when `stop` is set.
pub(crate) fn merge_worker(
    txs: Vec<UnboundedSender<MergeRequest>>,
    mut specs: Vec<MergeSpec>,
    stop: Arc<AtomicBool>,
) {
    if specs.is_empty() || txs.is_empty() {
        return;
    }
    let reply_timeout = Duration::from_millis(500);
    let mut next_fire: Vec<Instant> = specs.iter().map(|s| Instant::now() + s.period).collect();

    while !stop.load(Ordering::Relaxed) {
        // Park until the soonest fire, in ≤50ms slices so `stop` stays
        // responsive.
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
            std::thread::sleep(nap);
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let now = Instant::now();
        for (i, spec) in specs.iter_mut().enumerate() {
            if now >= next_fire[i] {
                next_fire[i] = now + spec.period;
                probe_and_fold(spec, &txs, reply_timeout);
            }
        }
    }

    // Best-effort final pass — the last sub-interval is otherwise lost
    // (shards may already have exited, in which case `send` fails and we
    // skip them silently).
    for spec in specs.iter_mut() {
        probe_and_fold(spec, &txs, Duration::from_millis(100));
    }
}

fn probe_and_fold(spec: &mut MergeSpec, txs: &[UnboundedSender<MergeRequest>], timeout: Duration) {
    for tx in txs {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if tx
            .send(MergeRequest {
                type_id: spec.type_id,
                reply: reply_tx,
            })
            .is_err()
        {
            continue; // shard gone
        }
        if let Ok(Some(boxed)) = reply_rx.recv_timeout(timeout) {
            (spec.fold)(spec.primary.as_mut(), boxed);
        }
    }
    if let Some(obs) = &spec.observe {
        obs(spec.primary.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;
    use crate::ctx::StateMap;

    #[derive(Default)]
    struct Counter(u64);

    /// End-to-end worker↔shard protocol without AF_PACKET: two fake
    /// "shards" (each an async loop mimicking the run-loop merge branch)
    /// each contribute `delta` once; the worker folds into the grand
    /// total and the observer records it.
    #[test]
    fn worker_folds_each_shard_and_observes_grand_total() {
        let stop = Arc::new(AtomicBool::new(false));
        let num_shards: u64 = 2;
        let delta: u64 = 5;

        let observed = Arc::new(AtomicU64::new(0));
        let mut spec = MergeSpec::new::<Counter, _>(
            Duration::from_millis(20),
            |p: &mut Counter, t: Counter| {
                p.0 += t.0;
            },
        );
        {
            let observed = Arc::clone(&observed);
            spec.set_observe::<Counter, _>(move |c: &Counter| {
                observed.store(c.0, Ordering::Relaxed);
            });
        }

        // Fake shards: each holds a `Counter(delta)` and answers exactly
        // one probe with it (take-and-reset → subsequent probes get None).
        let mut txs = Vec::new();
        let mut shard_handles = Vec::new();
        for _ in 0..num_shards {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MergeRequest>();
            txs.push(tx);
            let stop = Arc::clone(&stop);
            shard_handles.push(std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let mut state = StateMap::default();
                    state.get_or_init_mut::<Counter>().0 = delta;
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        tokio::select! {
                            req = rx.recv() => match req {
                                Some(req) => {
                                    let taken = state.take_dyn(req.type_id);
                                    let _ = req.reply.send(taken);
                                }
                                None => break,
                            },
                            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                        }
                    }
                });
            }));
        }

        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || merge_worker(txs, vec![spec], worker_stop));

        std::thread::sleep(Duration::from_millis(120));
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        for h in shard_handles {
            let _ = h.join();
        }

        // Each shard contributed `delta` exactly once.
        assert_eq!(observed.load(Ordering::Relaxed), num_shards * delta);
    }
}
