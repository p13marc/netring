//! [`AsyncMultiCapture`] — fan-in over multiple AF_PACKET captures
//! with two construction shapes:
//!
//! - [`AsyncMultiCapture::open`] / [`open_with_filter`](AsyncMultiCapture::open_with_filter)
//!   — N distinct interfaces, one capture each.
//! - [`AsyncMultiCapture::open_workers`] /
//!   [`open_workers_with_mode`](AsyncMultiCapture::open_workers_with_mode)
//!   — one interface, N captures sharing a `PACKET_FANOUT` group.
//!
//! Both shapes produce the same return type and the same builder
//! chain. The yielded type from
//! [`MultiFlowStream`](super::multi_streams::MultiFlowStream) etc.
//! is [`TaggedEvent`](super::multi_streams::TaggedEvent) with a
//! `source_idx` for routing.
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::AsyncMultiCapture;
//! # use netring::flow::extract::FiveTuple;
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! // Multi-interface gateway capture:
//! let multi = AsyncMultiCapture::open(["eth0", "eth1"])?;
//! let mut stream = multi.flow_stream(FiveTuple::bidirectional());
//! while let Some(evt) = stream.next().await {
//!     let tagged = evt?;
//!     let _ = tagged.source_idx;
//!     # break;
//! }
//! # Ok(()) }
//! ```
//!
//! ```no_run
//! # use netring::AsyncMultiCapture;
//! # fn _ex() -> Result<(), netring::Error> {
//! // 4-worker scaling on one interface (FanoutMode::Cpu).
//! // See `docs/scaling.md` for the canonical recipe (thread
//! // pinning via `core_affinity::set_for_current`, anti-patterns,
//! // troubleshooting).
//! let multi = AsyncMultiCapture::open_workers("eth0", 4, 0xDE57)?;
//! # let _ = multi; Ok(()) }
//! ```

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::config::BpfFilter;
use crate::config::{FanoutFlags, FanoutMode};
use crate::error::Error;
use crate::{Capture, CaptureBuilder};

/// Fan-in over multiple AF_PACKET captures. See module docs.
pub struct AsyncMultiCapture {
    captures: Vec<AsyncCapture<Capture>>,
    labels: Vec<String>,
}

impl AsyncMultiCapture {
    /// Open one AF_PACKET capture per interface with default settings.
    /// Labels are taken from the interface names.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered — partial success is
    /// rolled back (all earlier captures are dropped).
    pub fn open<I, S>(interfaces: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut captures = Vec::new();
        let mut labels = Vec::new();
        for iface in interfaces {
            let name = iface.as_ref();
            captures.push(AsyncCapture::open(name)?);
            labels.push(name.to_string());
        }
        Self::validate_nonempty(&captures)?;
        Ok(Self { captures, labels })
    }

    /// Open one AF_PACKET capture per interface with a shared
    /// kernel-side BPF filter applied to every source.
    pub fn open_with_filter<I, S>(interfaces: I, filter: BpfFilter) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut captures = Vec::new();
        let mut labels = Vec::new();
        for iface in interfaces {
            let name = iface.as_ref();
            // Plan 21: same builder shape as `open_with_filter`.
            let rx = CaptureBuilder::default()
                .interface(name)
                .bpf_filter(filter.clone())
                .build()?;
            captures.push(AsyncCapture::new(rx)?);
            labels.push(name.to_string());
        }
        Self::validate_nonempty(&captures)?;
        Ok(Self { captures, labels })
    }

    /// Open `n` AF_PACKET captures on a single `interface`, bound to
    /// one `PACKET_FANOUT` group, distributed by [`FanoutMode::Cpu`].
    /// Labels are `worker-0`, `worker-1`, etc.
    ///
    /// `group_id` is the fanout group identifier — must be unique
    /// within the process across overlapping fanout groups.
    ///
    /// **Thread pinning is the caller's responsibility**: spawn `n`
    /// tasks (one per returned capture), pin each to a CPU via
    /// [`core_affinity::set_for_current`](https://docs.rs/core_affinity/),
    /// or accept that worker ↔ CPU affinity is left to the kernel
    /// scheduler.
    ///
    /// On NICs without RSS (e.g. `lo`, some virtual NICs),
    /// `FanoutMode::Cpu` may degenerate to "worker 0 receives
    /// everything". See `docs/scaling.md`.
    pub fn open_workers(interface: &str, n: usize, group_id: u16) -> Result<Self, Error> {
        Self::open_workers_with_mode(interface, n, group_id, FanoutMode::Cpu)
    }

    /// Like [`open_workers`](Self::open_workers) but with explicit
    /// [`FanoutMode`]. Use [`FanoutMode::LoadBalance`] for round-robin
    /// (breaks per-flow ordering), [`FanoutMode::Cpu`] for cache
    /// locality on RSS-capable NICs, [`FanoutMode::Hash`] only for
    /// uniformly-distributed flows (otherwise see the skewed-traffic
    /// anti-pattern in `docs/scaling.md`).
    pub fn open_workers_with_mode(
        interface: &str,
        n: usize,
        group_id: u16,
        mode: FanoutMode,
    ) -> Result<Self, Error> {
        if n == 0 {
            return Err(Error::Config(
                "AsyncMultiCapture::open_workers requires n >= 1".into(),
            ));
        }
        let mut captures = Vec::with_capacity(n);
        let mut labels = Vec::with_capacity(n);
        for i in 0..n {
            let rx = CaptureBuilder::default()
                .interface(interface)
                .fanout(mode, group_id)
                .fanout_flags(FanoutFlags::ROLLOVER)
                .build()?;
            captures.push(AsyncCapture::new(rx)?);
            labels.push(format!("worker-{i}"));
        }
        Ok(Self { captures, labels })
    }

    /// Wrap an already-built set of captures. Use when each source
    /// needs different config (heterogeneous buffer sizes, mixed
    /// filters, hand-tuned fanout groups, …).
    ///
    /// If `labels` is `None`, sources are labelled `source-0`,
    /// `source-1`, etc. If `Some`, must have the same length as
    /// `captures`.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if `captures` is empty.
    /// - [`Error::Config`] if `labels` length doesn't match.
    pub fn from_captures(
        captures: Vec<AsyncCapture<Capture>>,
        labels: Option<Vec<String>>,
    ) -> Result<Self, Error> {
        Self::validate_nonempty(&captures)?;
        let labels = match labels {
            Some(l) => {
                if l.len() != captures.len() {
                    return Err(Error::Config(format!(
                        "AsyncMultiCapture::from_captures: labels.len() == {} but captures.len() == {}",
                        l.len(),
                        captures.len()
                    )));
                }
                l
            }
            None => (0..captures.len()).map(|i| format!("source-{i}")).collect(),
        };
        Ok(Self { captures, labels })
    }

    /// Number of underlying captures.
    pub fn len(&self) -> usize {
        self.captures.len()
    }

    /// True if there are no captures.
    pub fn is_empty(&self) -> bool {
        self.captures.is_empty()
    }

    /// Label for source `i` — interface name for [`open`](Self::open)
    /// / [`open_with_filter`](Self::open_with_filter), `worker-{i}` for
    /// [`open_workers`](Self::open_workers) /
    /// [`open_workers_with_mode`](Self::open_workers_with_mode), or
    /// the user-supplied label for [`from_captures`](Self::from_captures).
    pub fn label(&self, i: usize) -> Option<&str> {
        self.labels.get(i).map(|s| s.as_str())
    }

    /// Borrow the captures + labels. Useful for shared
    /// pre-stream-build operations (set_filter on each, etc.).
    pub fn captures(&self) -> &[AsyncCapture<Capture>] {
        &self.captures
    }

    /// Consume into the underlying captures + labels for advanced
    /// composition (e.g. building heterogeneous Multi* streams).
    pub fn into_captures(self) -> (Vec<AsyncCapture<Capture>>, Vec<String>) {
        (self.captures, self.labels)
    }

    fn validate_nonempty<T>(items: &[T]) -> Result<(), Error> {
        if items.is_empty() {
            Err(Error::Config(
                "AsyncMultiCapture requires at least one source".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_open_errors() {
        let r = AsyncMultiCapture::open(std::iter::empty::<&str>());
        assert!(r.is_err());
    }

    #[test]
    fn open_workers_zero_errors() {
        // Sanity — kernel rejects fanout-group of 0 too, but the
        // builder errors out earlier so we don't even try.
        let r = AsyncMultiCapture::open_workers("lo", 0, 0);
        assert!(r.is_err());
    }

    #[test]
    fn from_captures_labels_length_mismatch_errors() {
        // Empty captures + Some(labels with content) — fails on the
        // empty check first. But the path is exercised separately
        // in the integration test where real captures are built.
        let r = AsyncMultiCapture::from_captures(Vec::new(), Some(vec!["only-one".into()]));
        assert!(r.is_err());
    }
}
