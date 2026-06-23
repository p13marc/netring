//! Export completed flows to a columnar Parquet file (issue #51).
//!
//! Wires [`ParquetFlowExporter`] via `MonitorBuilder::export_flows` — every
//! flow netring finalizes is written as a row in `flows.parquet`, queryable
//! with DataFusion / DuckDB / Polars / Tenzir. The footer is written when the
//! monitor (and the exporter) drop at shutdown.
//!
//! ```sh
//! cargo run -p netring-exporters --example parquet_flows --features parquet -- eth0 flows.parquet
//! ```

use std::time::Duration;

use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring_exporters::ParquetFlowExporter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    let out = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "flows.parquet".to_string());

    let exporter = ParquetFlowExporter::create(&out)?;

    eprintln!("# writing flow rows to {out} from {iface} (Ctrl-C to stop)");
    Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .export_flows(exporter)
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
