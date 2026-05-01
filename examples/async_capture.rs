//! Async packet capture with tokio.
//!
//! Usage: cargo run --example async_capture --features tokio -- [interface]

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::CaptureBuilder;
    use netring::async_adapters::tokio_adapter::AsyncCapture;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Async capture on {iface}...");

    let rx = CaptureBuilder::default()
        .interface(&iface)
        .block_timeout_ms(100)
        .build()?;

    let mut async_cap = AsyncCapture::new(rx)?;
    let mut count = 0;

    loop {
        let mut guard = async_cap.readable().await?;
        if let Some(batch) = guard.next_batch() {
            for pkt in &batch {
                println!(
                    "[{}.{:09}] {} bytes",
                    pkt.timestamp().sec,
                    pkt.timestamp().nsec,
                    pkt.len(),
                );
                count += 1;
            }
        }
        if count >= 50 {
            break;
        }
    }

    eprintln!("{count} packets captured");
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!(
        "This example requires the 'tokio' feature: cargo run --example async_capture --features tokio"
    );
}
