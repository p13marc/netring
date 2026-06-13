//! 0.22 §5.2 — `LayerSpec`: cloneable config layers via the blanket
//! impl, non-`Clone` layers via `LayerFactory`, and `ShardedRunner::layer`
//! minting an independent layer per shard.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use netring::config::FanoutMode;
use netring::layer::{Layer, LayerFactory, LayerSpec};
use netring::monitor::ShardedRunner;
use netring::prelude::*;

#[test]
fn cloneable_config_layers_are_layer_specs() {
    // The blanket `impl<L: Layer + Clone + Sync> LayerSpec`.
    fn assert_spec<L: LayerSpec>(_: &L) {}
    assert_spec(&MinSeverity::warning());
    assert_spec(&DedupeAnomalies::within(Duration::from_secs(1)));
    assert_spec(&RateLimitAnomalies::new(10, Duration::from_secs(1)));
    assert_spec(&Sample::at_rate(0.5));

    // Each instantiate() yields a fresh boxed Layer.
    let spec = DedupeAnomalies::within(Duration::from_secs(1));
    let _a: Box<dyn Layer> = spec.instantiate();
    let _b: Box<dyn Layer> = spec.instantiate();
}

#[test]
fn layer_factory_wraps_non_clone_layers() {
    // `Tee` isn't Clone/Sync; the factory mints a fresh one per call,
    // and we can prove each call runs.
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let factory = LayerFactory(|| -> Box<dyn Layer> {
        CALLS.fetch_add(1, Ordering::Relaxed);
        Box::new(Tee::factory(|| Box::new(StdoutSink::default())))
    });
    let _l1 = factory.instantiate();
    let _l2 = factory.instantiate();
    assert_eq!(CALLS.load(Ordering::Relaxed), 2);
}

#[test]
fn sharded_runner_accepts_layer_specs() {
    // Build a 2-shard runner with a per-shard MinSeverity layer; just
    // assert the builder wiring compiles + accepts the spec (running
    // needs CAP_NET_RAW).
    let _runner = ShardedRunner::new("lo", FanoutMode::Cpu, 42, 2, |_cpu| {
        Monitor::builder()
            .interface("lo")
            .fanout(FanoutMode::Cpu, 42)
            .protocol::<Tcp>()
            .sink(StdoutSink::default())
            .build()
    })
    .layer(MinSeverity::warning())
    .layer(LayerFactory(|| -> Box<dyn Layer> {
        Box::new(DedupeAnomalies::within(Duration::from_secs(60)))
    }));
}
