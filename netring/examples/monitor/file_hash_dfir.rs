//! 0.21 I.5: file-hash DFIR demo — flags executable payloads
//! served over plain HTTP via flowscope's `Sha256Sink` + `FileType`.
//!
//! Hashes each HTTP response body, classifies the first 64 bytes
//! via magic-byte sniffing, and emits an anomaly when the file
//! type is `Pe` / `Elf` / `MachO` (binary executables shipped
//! unencrypted — a classic supply-chain / drive-by indicator).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_file_hash_dfir \
//!     --features "tokio,flow,http" -- eth0
//! ```

use std::time::Duration;

use flowscope::detect::file::{FileHashSink, FileType, Sha256Sink};
use flowscope::http::HttpMessage;
use netring::prelude::*;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("file-hash-dfir")
        .protocol::<Http>()
        .on_ctx::<Http>(|msg: &HttpMessage, ctx: &mut Ctx<'_>| {
            // Only hash response bodies — request bodies are
            // usually form data, not payloads worth flagging.
            if let HttpMessage::Response(r) = msg
                && !r.body.is_empty()
            {
                let mut sink = Sha256Sink::default();
                sink.update(&r.body);
                let event = sink.finish();
                // Flag executable mime types over plaintext HTTP.
                match event.file_type {
                    FileType::Pe | FileType::Elf | FileType::MachO => {
                        ctx.emit("BinaryOverHttp", Severity::Warning)
                            .with("file_type", format!("{:?}", event.file_type))
                            .with("hash", event.hash_hex.clone())
                            .with_metric("bytes", event.bytes as f64)
                            .emit();
                    }
                    _ => {}
                }
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
