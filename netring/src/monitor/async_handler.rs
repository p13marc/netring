//! Async handler trait + blanket impls.
//!
//! [`AsyncHandler`] is the async sibling of [`super::Handler`]:
//! a callable that runs once per event of type `E`, returns a
//! `Result<()>` future, and is stored separately so sync handlers
//! never pay the boxed-future cost.
//!
//! ## Phase D shape — payload-only async
//!
//! Async handlers receive **only the typed payload** —
//! no `&mut Ctx<'_>` access. The lifetime gymnastics for
//! ctx-bearing async handlers (HRTBs over `Ctx<'a>`) don't
//! compose cleanly in stable Rust, and the common case for
//! `on_async` is I/O (Redis pipeline, Kafka producer,
//! HTTP push) where the handler captures its own
//! `Arc<Pool>` and doesn't need shared state.
//!
//! Users who need to mutate shared state from an async path can:
//! 1. Use a sync `on::<E>` handler to update the state, then
//!    submit a job (e.g. through a tokio mpsc) to a background
//!    async worker that performs the I/O.
//! 2. Capture an `Arc<Mutex<…>>` or atomic in the async closure;
//!    state lives outside the framework.
//! 3. Wire a `ChannelSink` (Phase C.2) as the anomaly sink; an
//!    async task drains the channel and does the I/O downstream.
//!
//! ## Allocation cost
//!
//! Each async-handler dispatch produces one boxed future per
//! handler per event. Sync handlers in Phase B cost zero
//! allocations — prefer `on` over `on_async` when the body
//! doesn't actually `.await`.

use std::future::Future;
use std::pin::Pin;

use crate::error::Result;
use crate::protocol::event_typed::Event;

/// Boxed future returned by async handler calls.
///
/// `'static` because the user-supplied closure receives `&payload`
/// for a dispatch-bounded lifetime and is expected to do its own
/// borrowing/ownership inside the future body.
///
/// `+ Send` (since 0.23) so the boxed future can be held across an
/// `.await` in a `Send` run-loop future — this is what lets
/// `Monitor::run_for(..)` be `tokio::spawn`'d. The bound mirrors
/// `tokio::spawn`'s own requirement: anything you `.await` inside an
/// `on_async` handler must be `Send`. Handlers that capture
/// `Arc<…>` and do network/disk I/O (the canonical case) already
/// satisfy this; the rare handler holding a non-`Send` guard across
/// its own `.await` must move that work behind a `ChannelSink` or an
/// `Arc<Mutex<…>>` instead.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Async counterpart of [`super::Handler`]. Only one arity:
/// `Fn(&E::Payload) -> impl Future<Output = Result<()>> + Send`.
pub trait AsyncHandler<E: Event>: Send + Sync + 'static {
    /// Invoke the handler. The boxed future is awaited to
    /// completion before the run loop moves on.
    fn call(&self, payload: &E::Payload) -> BoxFuture<Result<()>>;
}

/// Blanket impl for async closures. `Fut: Send` (since 0.23) keeps
/// the run-loop future `Send`; see [`BoxFuture`].
impl<E, F, Fut> AsyncHandler<E> for F
where
    E: Event,
    F: Fn(&E::Payload) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    #[inline]
    fn call(&self, p: &E::Payload) -> BoxFuture<Result<()>> {
        Box::pin(self(p))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use flowscope::Timestamp;

    use super::*;
    use crate::protocol::builtin::Tcp;
    use crate::protocol::event_typed::FlowStarted;

    fn dummy_flow_started() -> FlowStarted<Tcp> {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        );
        FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_closure_awaits_to_completion() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);

        let handler = move |_p: &FlowStarted<Tcp>| {
            let c = Arc::clone(&c);
            async move {
                tokio::task::yield_now().await;
                c.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        };

        let evt = dummy_flow_started();
        AsyncHandler::<FlowStarted<Tcp>>::call(&handler, &evt)
            .await
            .unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_handler_can_capture_arc_state() {
        // Simulate a downstream resource — the canonical use case
        // for on_async (Redis pool, Kafka producer, HTTP client).
        struct PoolStub {
            calls: AtomicU32,
        }
        let pool = Arc::new(PoolStub {
            calls: AtomicU32::new(0),
        });
        let pool_h = Arc::clone(&pool);

        let handler = move |_p: &FlowStarted<Tcp>| {
            let pool = Arc::clone(&pool_h);
            async move {
                tokio::task::yield_now().await;
                pool.calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        };

        let evt = dummy_flow_started();
        AsyncHandler::<FlowStarted<Tcp>>::call(&handler, &evt)
            .await
            .unwrap();
        AsyncHandler::<FlowStarted<Tcp>>::call(&handler, &evt)
            .await
            .unwrap();
        assert_eq!(pool.calls.load(Ordering::Relaxed), 2);
    }
}
