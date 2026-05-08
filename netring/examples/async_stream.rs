//! Async packet capture as a `Stream` of owned batches.
//!
//! Demonstrates [`PacketStream`] composing with futures combinators
//! (`take_while`, `flat_map`, ...). Useful when you want stream-style
//! ergonomics over batched capture.
//!
//! Usage: cargo run --example async_stream --features tokio -- [interface] [duration_secs]

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::Capture;
    use netring::async_adapters::tokio_adapter::{AsyncCapture, PacketStream};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    eprintln!("Streaming on {iface} for {secs}s...");

    let rx = Capture::builder()
        .interface(&iface)
        .block_timeout_ms(50)
        .build()?;
    let cap = AsyncCapture::new(rx)?;
    let mut stream = std::pin::pin!(PacketStream::new(cap));

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;

    // Hand-poll the stream rather than depending on futures::StreamExt to
    // keep the example dependency-free. In real code you'd typically:
    //
    //     use futures::StreamExt;
    //     while let Some(batch) = stream.next().await { ... }
    //
    use futures_core::Stream;
    use std::future::poll_fn;

    loop {
        if Instant::now() >= deadline {
            break;
        }
        let timeout_left = deadline.saturating_duration_since(Instant::now());

        // Poll the stream with a deadline-bounded sleep.
        tokio::select! {
            item = poll_fn(|cx| Stream::poll_next(stream.as_mut(), cx)) => {
                match item {
                    Some(Ok(batch)) => {
                        total_packets += batch.len() as u64;
                        total_bytes += batch.iter().map(|p| p.data.len() as u64).sum::<u64>();
                    }
                    Some(Err(e)) => {
                        eprintln!("stream error: {e}");
                        break;
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(timeout_left) => break,
        }
    }

    eprintln!("Captured {total_packets} packets, {total_bytes} bytes");
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!(
        "This example requires the 'tokio' feature: cargo run --example async_stream --features tokio"
    );
}
