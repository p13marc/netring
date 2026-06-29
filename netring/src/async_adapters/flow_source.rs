//! [`AsyncFlowSource`] — the source-agnostic feed driving
//! [`FlowStream`](crate::async_adapters::flow_stream::FlowStream).
//!
//! `FlowStream` originally drained an [`AsyncCapture`] (AF_PACKET) directly.
//! AF_XDP ([`AsyncXdpCapture`](crate::AsyncXdpCapture)) has the same job —
//! poll for readiness, drain a batch, feed each packet's
//! [`PacketView`](flowscope::PacketView) to a flow tracker — but a different
//! readiness/batch surface and no AF_PACKET [`Packet`](crate::Packet) to lend.
//!
//! This trait captures exactly the slice `FlowStream` needs: *drive one
//! readiness+drain cycle, handing each packet to a sink*. The flow-tracking
//! logic (dedup, pcap tap, monotonic clamp, `tracker.track`, sweep) stays in
//! `FlowStream` and is shared verbatim across both backends (issue #104).

use std::task::{Context, Poll};

use flowscope::PacketView;

use crate::packet::PacketDirection;
// `Timestamp` is only referenced by the AF_XDP `view_from_parts` helper.
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
use crate::packet::Timestamp;

/// One packet handed to a `FlowStream` sink during a drain cycle.
///
/// Carries the zero-copy [`PacketView`] for flow extraction plus the raw
/// parts (`data` / `direction` / `original_len`) the dedup and pcap-tap legs
/// need — neither of which can borrow a backend-specific packet type. The
/// `view` timestamp is the source's *unclamped* timestamp (the monotonic
/// clamp is applied by `FlowStream` after dedup/tap, matching the original
/// ordering).
pub(crate) struct SourcePacket<'a> {
    pub view: PacketView<'a>,
    pub data: &'a [u8],
    pub direction: PacketDirection,
    // Read only by the pcap-tap leg; without `pcap` it is genuinely unused.
    #[cfg_attr(not(feature = "pcap"), allow(dead_code))]
    pub original_len: usize,
}

/// Outcome of one [`AsyncFlowSource::poll_drain`] cycle.
pub(crate) enum DrainOutcome {
    /// A batch was drained — the sink ran for each packet (possibly zero).
    Drained,
    /// The source signalled readiness but yielded no batch this cycle;
    /// readiness has already been cleared internally so the caller should
    /// retry the poll loop (it will register a fresh wake-up).
    Idle,
}

/// Source-agnostic async packet feed for
/// [`FlowStream`](crate::async_adapters::flow_stream::FlowStream).
///
/// Implemented by AF_PACKET ([`AsyncCapture`](crate::AsyncCapture)) and
/// AF_XDP ([`AsyncXdpCapture`](crate::AsyncXdpCapture)).
pub(crate) trait AsyncFlowSource {
    /// Poll for readiness and drain at most one batch, invoking `sink` for
    /// each packet. Returns `Pending` if the source is not ready;
    /// `Ready(Ok(Drained))` after a batch (sink ran); `Ready(Ok(Idle))` on a
    /// spurious readiness with no batch; `Ready(Err(_))` on I/O error.
    fn poll_drain(
        &mut self,
        cx: &mut Context<'_>,
        sink: &mut dyn FnMut(SourcePacket<'_>),
    ) -> Poll<std::io::Result<DrainOutcome>>;
}

// ── AF_PACKET: AsyncCapture<S> ─────────────────────────────────────────────

use std::os::unix::io::AsRawFd;

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::traits::PacketSource;

impl<S> AsyncFlowSource for AsyncCapture<S>
where
    S: PacketSource + AsRawFd,
{
    fn poll_drain(
        &mut self,
        cx: &mut Context<'_>,
        sink: &mut dyn FnMut(SourcePacket<'_>),
    ) -> Poll<std::io::Result<DrainOutcome>> {
        let mut guard = match self.poll_read_ready_mut(cx) {
            Poll::Ready(Ok(g)) => g,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let inner = guard.get_inner_mut();
        if let Some(batch) = inner.next_batch() {
            for pkt in &batch {
                sink(SourcePacket {
                    view: pkt.view(),
                    data: pkt.data(),
                    direction: pkt.direction(),
                    original_len: pkt.original_len(),
                });
            }
            drop(batch);
            Poll::Ready(Ok(DrainOutcome::Drained))
        } else {
            guard.clear_ready();
            Poll::Ready(Ok(DrainOutcome::Idle))
        }
    }
}

/// Build a [`PacketView`] for a backend that exposes only raw bytes + an
/// optional timestamp + RX metadata (AF_XDP). Falls back to a software
/// timestamp when the NIC supplied none.
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
#[inline]
pub(crate) fn view_from_parts(
    data: &[u8],
    ts: Option<Timestamp>,
    rx_metadata: flowscope::RxMetadata,
) -> PacketView<'_> {
    let ts = ts.unwrap_or_else(crate::async_adapters::flow_stream::current_timestamp);
    PacketView::new(data, ts).with_rx_metadata(rx_metadata)
}

// ── AF_XDP: AsyncXdpCapture ────────────────────────────────────────────────

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl AsyncFlowSource for crate::AsyncXdpCapture {
    fn poll_drain(
        &mut self,
        cx: &mut Context<'_>,
        sink: &mut dyn FnMut(SourcePacket<'_>),
    ) -> Poll<std::io::Result<DrainOutcome>> {
        // The multi-socket round-robin lives on `AsyncXdpCapture` itself so it
        // can do disjoint field borrows (`sockets` vs `cursor`); map its
        // `netring::Error` back to the trait's `io::Error`.
        match self.poll_drain_views(cx, sink) {
            Poll::Ready(Ok(outcome)) => Poll::Ready(Ok(outcome)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(match e {
                crate::error::Error::Io(io) => io,
                other => std::io::Error::other(other),
            })),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time wiring assertions for issue #104: both backends implement
    /// the source trait, and the AF_XDP fan-in types are real `Stream`s
    /// yielding the tagged flow events. (The runtime AF_XDP path needs a NIC
    /// + `CAP_NET_RAW`, so it is exercised by the root-gated suite.)
    #[allow(dead_code)]
    fn _assert_impls() {
        fn is_flow_source<T: AsyncFlowSource>() {}
        fn is_stream<T: futures_core::Stream>() {}

        type Ext = flowscope::extract::FiveTuple;
        is_flow_source::<crate::AsyncCapture<crate::Capture>>();
        is_stream::<
            crate::async_adapters::flow_stream::FlowStream<
                crate::AsyncCapture<crate::Capture>,
                Ext,
            >,
        >();

        #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
        {
            use flowscope::{DatagramParser, FlowSide, SessionParser, Timestamp};

            #[derive(Default, Clone)]
            struct SParser;
            impl SessionParser for SParser {
                type Message = ();
                fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
                fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
            }
            #[derive(Default, Clone)]
            struct DParser;
            impl DatagramParser for DParser {
                type Message = ();
                fn parse(&mut self, _: &[u8], _: FlowSide, _: Timestamp, _: &mut Vec<()>) {}
            }

            is_flow_source::<crate::AsyncXdpCapture>();
            is_stream::<crate::async_adapters::flow_stream::FlowStream<crate::AsyncXdpCapture, Ext>>(
            );
            is_stream::<crate::async_adapters::multi_streams::XdpMultiFlowStream<Ext>>();
            // AF_XDP tap merge (#105 Phase B over AF_XDP): one shared tracker.
            is_stream::<
                crate::async_adapters::multi_streams::MergedFlowStream<crate::AsyncXdpCapture, Ext>,
            >();
            // AF_XDP L7 streams (this turn): session + datagram over AF_XDP.
            is_stream::<
                crate::async_adapters::session_stream::SessionStream<
                    crate::AsyncXdpCapture,
                    Ext,
                    SParser,
                >,
            >();
            is_stream::<
                crate::async_adapters::datagram_stream::DatagramStream<
                    crate::AsyncXdpCapture,
                    Ext,
                    DParser,
                >,
            >();
            // AF_XDP multi-interface L7 fan-in.
            is_stream::<crate::async_adapters::multi_streams::XdpMultiSessionStream<Ext, SParser>>(
            );
            is_stream::<crate::async_adapters::multi_streams::XdpMultiDatagramStream<Ext, DParser>>(
            );
        }
    }
}
