//! Throughput benchmarks for netring.
//!
//! Benchmarks that don't require CAP_NET_RAW measure iterator and conversion
//! performance using synthetic data. Network benchmarks require privileges.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use netring::Timestamp;

fn bench_timestamp_conversion(c: &mut Criterion) {
    let ts = Timestamp::new(1_700_000_000, 123_456_789);

    let mut group = c.benchmark_group("timestamp");
    group.throughput(Throughput::Elements(1));

    group.bench_function("to_system_time", |b| {
        b.iter(|| std::hint::black_box(ts.to_system_time()))
    });

    group.bench_function("to_duration", |b| {
        b.iter(|| std::hint::black_box(ts.to_duration()))
    });

    group.finish();
}

fn bench_packet_status_decode(c: &mut Criterion) {
    use netring::PacketStatus;

    let raw_flags: u32 = 0x01 | 0x02 | 0x10 | 0x80; // USER | COPY | VLAN_VALID | CSUM_VALID

    c.bench_function("packet_status_from_raw", |b| {
        b.iter(|| std::hint::black_box(PacketStatus::from_raw(std::hint::black_box(raw_flags))))
    });
}

criterion_group!(
    benches,
    bench_timestamp_conversion,
    bench_packet_status_decode
);
criterion_main!(benches);
