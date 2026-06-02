//! `Conversation` aggregate demo.
//!
//! Captures live, yields one async iterator per flow that emits
//! both directions' bytes plus a terminal Closed marker. Way less
//! boilerplate than `with_async_reassembler(channel_factory(...))`.
//!
//! Usage:
//!     cargo run -p netring --example async_flow_conversations --features tokio,flow

use std::env;

use futures::StreamExt;
use netring::AsyncCapture;
use netring::async_adapters::conversation::ConversationChunk;
use netring::flow::extract::FiveTuple;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    eprintln!("listening on {iface} (Ctrl+C to stop)...");

    let cap = AsyncCapture::open(&iface)?;
    let mut convs = cap
        .flow_stream(FiveTuple::bidirectional())
        .into_conversations();

    while let Some(conv) = convs.next().await {
        let mut conv = conv?;
        let key = conv.key;
        eprintln!("→ flow {} <-> {}", key.a, key.b);

        // Spawn a task per conversation so the outer stream keeps
        // accepting new flows while we drain this one.
        tokio::spawn(async move {
            let mut init_bytes = 0u64;
            let mut resp_bytes = 0u64;
            while let Some(chunk) = conv.next_chunk().await {
                match chunk {
                    ConversationChunk::Initiator(b) => init_bytes += b.len() as u64,
                    ConversationChunk::Responder(b) => resp_bytes += b.len() as u64,
                    ConversationChunk::Closed { reason } => {
                        eprintln!(
                            "← flow {} <-> {}  closed={reason:?}  init_bytes={init_bytes}  resp_bytes={resp_bytes}",
                            key.a, key.b
                        );
                        break;
                    }
                }
            }
        });
    }
    Ok(())
}
