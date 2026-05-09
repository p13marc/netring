#![allow(missing_docs)]

//! Async TCP reassembly hooks for the [`crate::FlowStream`].
//!
//! Sync reassembly users should use [`flowscope::Reassembler`] +
//! [`flowscope::FlowDriver`]. This module is for tokio users who
//! want backpressure: the [`AsyncReassembler`]'s `segment` future
//! is awaited inline in `FlowStream::poll_next`, so a slow consumer
//! propagates pressure all the way to the kernel ring.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use flowscope::FlowSide;
use tokio::sync::mpsc;

/// Receives TCP segments for one direction of one session.
///
/// The flow stream awaits each `segment`/`fin`/`rst` future before
/// yielding the next event. Slow consumers backpressure the entire
/// pipeline.
///
/// `Bytes` (not `&[u8]`) so implementors can hold the payload
/// across `.await` points.
///
/// **Lifetimes**: methods take `&mut self` but return a `'static`
/// future. Implementors must clone or move whatever state they need
/// into the returned future — borrowing across `.await` from `self`
/// is not supported (this lets [`crate::FlowStream`] store the
/// pending future without a self-referential reference).
pub trait AsyncReassembler: Send + 'static {
    fn segment(
        &mut self,
        seq: u32,
        payload: Bytes,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    fn fin(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async {})
    }

    fn rst(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async {})
    }
}

/// Build an [`AsyncReassembler`] for a brand-new session, given its
/// key and side.
pub trait AsyncReassemblerFactory<K>: Send + 'static {
    type Reassembler: AsyncReassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
}

/// Common pattern: spawn a tokio task per (flow, side); feed its
/// receiver via mpsc with backpressure.
///
/// `make_sender` returns a `Sender<Bytes>` for each new (flow, side).
/// The returned `AsyncReassembler` does `tx.send(bytes).await` on
/// every segment, dropping the sender on `fin`/`rst` so the user's
/// spawned task exits naturally via `recv() → None`.
///
/// # Example
///
/// ```no_run
/// use bytes::Bytes;
/// use tokio::sync::mpsc;
/// use netring::AsyncCapture;
/// use netring::flow::extract::FiveTuple;
/// use netring::async_adapters::async_reassembler::channel_factory;
///
/// # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
/// use netring::flow::extract::FiveTupleKey;
/// let cap = AsyncCapture::open("eth0")?;
/// let mut stream = cap
///     .flow_stream(FiveTuple::bidirectional())
///     .with_async_reassembler(channel_factory(|_key: &FiveTupleKey, _side| {
///         let (tx, mut rx) = mpsc::channel::<Bytes>(64);
///         tokio::spawn(async move {
///             while let Some(_bytes) = rx.recv().await {
///                 // process bytes
///             }
///         });
///         tx
///     }));
/// # Ok(()) }
/// ```
pub fn channel_factory<K, F>(make_sender: F) -> ChannelFactory<K, F>
where
    F: FnMut(&K, FlowSide) -> mpsc::Sender<Bytes> + Send + 'static,
    K: Clone + Send + 'static,
{
    ChannelFactory {
        make_sender,
        _phantom: std::marker::PhantomData,
    }
}

/// Adapter built by [`channel_factory`].
pub struct ChannelFactory<K, F> {
    make_sender: F,
    _phantom: std::marker::PhantomData<fn(&K)>,
}

impl<K, F> AsyncReassemblerFactory<K> for ChannelFactory<K, F>
where
    F: FnMut(&K, FlowSide) -> mpsc::Sender<Bytes> + Send + 'static,
    K: Clone + Send + 'static,
{
    type Reassembler = ChannelReassembler;

    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> ChannelReassembler {
        ChannelReassembler {
            tx: Some((self.make_sender)(key, side)),
        }
    }
}

/// AsyncReassembler that pushes each segment's payload into a
/// `mpsc::Sender<Bytes>`. Backpressure: if the receiver is full,
/// `send().await` blocks until capacity is available.
///
/// On `fin`/`rst`, drops the sender so the receiver sees `None` and
/// the user's spawned task can exit.
pub struct ChannelReassembler {
    tx: Option<mpsc::Sender<Bytes>>,
}

impl AsyncReassembler for ChannelReassembler {
    fn segment(
        &mut self,
        _seq: u32,
        payload: Bytes,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        // Clone the sender into the future so the borrow on `self`
        // doesn't outlive this method. mpsc::Sender clone is cheap
        // (an Arc bump).
        let tx = self.tx.clone();
        Box::pin(async move {
            if let Some(tx) = tx {
                let _ = tx.send(payload).await;
            }
        })
    }

    fn fin(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        // Drop the sender so the receiver sees Closed.
        self.tx = None;
        Box::pin(async {})
    }

    fn rst(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.tx = None;
        Box::pin(async {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn channel_factory_dispatches_per_flow_and_side() {
        let counts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, FlowSide)>::new()));
        let counts_clone = counts.clone();
        let mut factory = channel_factory(move |key: &String, side: FlowSide| {
            counts_clone.lock().unwrap().push((key.clone(), side));
            let (tx, _rx) = mpsc::channel::<Bytes>(8);
            tx
        });

        let _r1 = factory.new_reassembler(&"flow-A".to_string(), FlowSide::Initiator);
        let _r2 = factory.new_reassembler(&"flow-A".to_string(), FlowSide::Responder);
        let _r3 = factory.new_reassembler(&"flow-B".to_string(), FlowSide::Initiator);

        let recorded = counts.lock().unwrap();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0].0, "flow-A");
        assert_eq!(recorded[0].1, FlowSide::Initiator);
        assert_eq!(recorded[1].1, FlowSide::Responder);
        assert_eq!(recorded[2].0, "flow-B");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn segment_pushes_to_channel() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(4);
        let mut r = ChannelReassembler { tx: Some(tx) };
        r.segment(0, Bytes::from_static(b"abc")).await;
        r.segment(3, Bytes::from_static(b"def")).await;
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"abc"));
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"def"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fin_closes_channel() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(4);
        let mut r = ChannelReassembler { tx: Some(tx) };
        r.segment(0, Bytes::from_static(b"x")).await;
        r.fin().await;
        // Receiver drains pending then sees Closed.
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"x"));
        assert_eq!(rx.recv().await, None);
    }
}
