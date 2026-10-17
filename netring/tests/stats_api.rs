//! Compile-level checks for the 0.32 statistics API (#186).
//!
//! A live stream implements both [`StreamCapture`] and [`MultiSource`]; with
//! both traits in scope `stream.capture_stats()` must resolve to exactly one
//! method. Before 0.32 both traits had a `capture_stats` (with different
//! return types and, on AF_PACKET, different meanings), so this file did not
//! compile: `error[E0034]: multiple applicable items in scope`.

#![cfg(all(feature = "tokio", feature = "flow"))]

use netring::flow::extract::FiveTuple;
use netring::{AsyncCapture, Capture, CaptureStats, Error, FlowStream, MultiSource, StreamCapture};

/// `capture_stats()` is the `StreamCapture` accessor, `ring_stats()` the
/// `MultiSource` one; both are lifetime totals of the same ring.
#[allow(dead_code)]
fn both_accessors(
    stream: &FlowStream<AsyncCapture<Capture>, FiveTuple>,
) -> (
    Result<CaptureStats, Error>,
    Option<Result<CaptureStats, Error>>,
) {
    let lifetime: Result<CaptureStats, Error> = stream.capture_stats();
    let ring: Option<Result<CaptureStats, Error>> = stream.ring_stats();
    (lifetime, ring)
}

/// The same through the trait objects the fan-ins hand out.
#[allow(dead_code)]
fn through_dyn(src: &dyn MultiSource<FiveTuple>) -> Option<Result<CaptureStats, Error>> {
    src.ring_stats()
}

#[test]
fn stream_exposes_capture_stats_and_ring_stats_unambiguously() {
    // Compiling this file is the test; reference the functions so they
    // are type-checked as used.
    let _ = both_accessors as fn(&_) -> _;
    let _ = through_dyn as fn(&_) -> _;
}
