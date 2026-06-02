//! Async capture as a `Stream`, consumed with `futures::StreamExt`.
//!
//! Adds `futures = "0.3"` as a dev-dependency for the `StreamExt`
//! combinators (`take`, `filter_map`, `fold`, ...). Compare with
//! `async_stream.rs` which hand-polls the stream to stay
//! dependency-free.
//!
//! Usage: cargo run --example async_streamext --features tokio -- [interface] [batch_count]

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use futures::StreamExt;
    use netring::AsyncCapture;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let batches: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    eprintln!("Streaming {batches} batches from {iface}...");

    let stream = AsyncCapture::open(&iface)?.into_stream();

    // Take N batches; for each, emit one (count, total_bytes) summary.
    // `filter_map` discards Err items (e.g. transient I/O glitches).
    let summaries: Vec<(usize, usize)> = stream
        .take(batches)
        .filter_map(|res| async move {
            res.ok().map(|batch| {
                let count = batch.len();
                let bytes: usize = batch.iter().map(|p| p.data.len()).sum();
                (count, bytes)
            })
        })
        .collect()
        .await;

    let total_packets: usize = summaries.iter().map(|(c, _)| c).sum();
    let total_bytes: usize = summaries.iter().map(|(_, b)| b).sum();

    eprintln!(
        "{} batches  →  {total_packets} packets  ·  {total_bytes} bytes",
        summaries.len()
    );
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!(
        "This example requires the 'tokio' feature: cargo run --example async_streamext --features tokio"
    );
}
