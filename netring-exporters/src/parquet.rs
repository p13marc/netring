//! Columnar **Parquet** flow export (issue #51).
//!
//! [`ParquetFlowExporter`] implements netring's
//! [`FlowExporter`](netring::export::FlowExporter), so it drops straight into
//! [`MonitorBuilder::export_flows`](netring::monitor::MonitorBuilder::export_flows):
//! every completed flow is buffered and written as a row in a Parquet file.
//!
//! Network/security logs are repetitive (IPs, ports, protocols) and queried
//! analytically, which is exactly what columnar Parquet is for — ~5–10×
//! compression plus column-pruning / predicate-pushdown, and a format that
//! drops into S3 / Security Lake / DataFusion / Tenzir. Built on the mature
//! `arrow` + `parquet` crates (the heaviest tree in the workspace, hence the
//! opt-in `parquet` feature).
//!
//! The schema uses OpenTelemetry / OCSF-style flat column names so files are
//! self-describing:
//!
//! | column | type |
//! |---|---|
//! | `network.protocol.name` | Utf8 |
//! | `source.address` / `source.port` | Utf8 / UInt16 |
//! | `destination.address` / `destination.port` | Utf8 / UInt16 |
//! | `source.packets` / `source.bytes` | UInt64 |
//! | `destination.packets` / `destination.bytes` | UInt64 |
//! | `flow.start` / `flow.end` | Timestamp(ns) |
//! | `flow.end_reason` | Utf8 (nullable) |
//!
//! ```no_run
//! # #[cfg(feature = "parquet")]
//! # fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use netring::monitor::Monitor;
//! use netring::protocol::builtin::Tcp;
//! use netring_exporters::ParquetFlowExporter;
//!
//! let _m = Monitor::builder()
//!     .interface("eth0")
//!     .protocol::<Tcp>()
//!     .export_flows(ParquetFlowExporter::create("flows.parquet")?)
//!     .build()?;
//! // The footer is written when the exporter is dropped (monitor shutdown).
//! # Ok(()) }
//! ```

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use arrow::array::{ArrayRef, StringArray, TimestampNanosecondArray, UInt16Array, UInt64Array};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use arrow::record_batch::RecordBatch;
use netring::Timestamp;
use netring::export::{FlowExporter, FlowRecord};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::errors::ParquetError;
use parquet::file::properties::WriterProperties;

/// Nanoseconds-since-epoch for a netring [`Timestamp`] (the Arrow
/// `Timestamp(Nanosecond)` physical value).
fn ts_nanos(ts: Timestamp) -> i64 {
    ts.sec as i64 * 1_000_000_000 + ts.nsec as i64
}

/// The flat Arrow schema for a flow row (OTel/OCSF-style column names).
fn flow_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("network.protocol.name", DataType::Utf8, false),
        Field::new("source.address", DataType::Utf8, false),
        Field::new("source.port", DataType::UInt16, false),
        Field::new("destination.address", DataType::Utf8, false),
        Field::new("destination.port", DataType::UInt16, false),
        Field::new("source.packets", DataType::UInt64, false),
        Field::new("source.bytes", DataType::UInt64, false),
        Field::new("destination.packets", DataType::UInt64, false),
        Field::new("destination.bytes", DataType::UInt64, false),
        Field::new(
            "flow.start",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            false,
        ),
        Field::new(
            "flow.end",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            false,
        ),
        Field::new("flow.end_reason", DataType::Utf8, true),
    ]))
}

/// Build one Arrow [`RecordBatch`] from a slice of buffered flow records.
fn build_batch(schema: &SchemaRef, recs: &[FlowRecord]) -> Result<RecordBatch, ParquetError> {
    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from_iter_values(
            recs.iter()
                .map(|r| format!("{:?}", r.proto).to_ascii_lowercase()),
        )),
        Arc::new(StringArray::from_iter_values(
            recs.iter().map(|r| r.a.ip().to_string()),
        )),
        Arc::new(UInt16Array::from_iter_values(
            recs.iter().map(|r| r.a.port()),
        )),
        Arc::new(StringArray::from_iter_values(
            recs.iter().map(|r| r.b.ip().to_string()),
        )),
        Arc::new(UInt16Array::from_iter_values(
            recs.iter().map(|r| r.b.port()),
        )),
        Arc::new(UInt64Array::from_iter_values(
            recs.iter().map(|r| r.packets_initiator),
        )),
        Arc::new(UInt64Array::from_iter_values(
            recs.iter().map(|r| r.bytes_initiator),
        )),
        Arc::new(UInt64Array::from_iter_values(
            recs.iter().map(|r| r.packets_responder),
        )),
        Arc::new(UInt64Array::from_iter_values(
            recs.iter().map(|r| r.bytes_responder),
        )),
        Arc::new(TimestampNanosecondArray::from_iter_values(
            recs.iter().map(|r| ts_nanos(r.start)),
        )),
        Arc::new(TimestampNanosecondArray::from_iter_values(
            recs.iter().map(|r| ts_nanos(r.end)),
        )),
        Arc::new(StringArray::from_iter(
            recs.iter().map(|r| r.reason.map(|x| format!("{x:?}"))),
        )),
    ];
    RecordBatch::try_new(schema.clone(), columns).map_err(|e| ParquetError::General(e.to_string()))
}

/// Writes completed flows to a Parquet file as columnar rows.
///
/// Records are buffered and written one Arrow row group per
/// [`batch_size`](Self::batch_size) flows (and on [`flush`](FlowExporter::flush)).
/// The Parquet **footer** — without which the file is unreadable — is written
/// when the exporter is dropped (at monitor shutdown), so no explicit close
/// call is needed.
pub struct ParquetFlowExporter<W: Write + Send> {
    writer: Option<ArrowWriter<W>>,
    schema: SchemaRef,
    buffer: Vec<FlowRecord>,
    batch_size: usize,
}

impl ParquetFlowExporter<File> {
    /// Create an exporter writing to a new Parquet file at `path`
    /// (ZSTD-compressed).
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = File::create(path)?;
        Self::new(file).map_err(|e| std::io::Error::other(e.to_string()))
    }
}

impl<W: Write + Send> ParquetFlowExporter<W> {
    /// Create an exporter over any writer (ZSTD-compressed, default batch size
    /// 1024 rows per group).
    pub fn new(writer: W) -> Result<Self, ParquetError> {
        let schema = flow_schema();
        let props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::default()))
            .build();
        let writer = ArrowWriter::try_new(writer, schema.clone(), Some(props))?;
        Ok(Self {
            writer: Some(writer),
            schema,
            buffer: Vec::new(),
            batch_size: 1024,
        })
    }

    /// Set the number of buffered flows per Arrow row group (default 1024).
    pub fn batch_size(mut self, n: usize) -> Self {
        self.batch_size = n.max(1);
        self
    }

    /// Write the buffered records as one row group, clearing the buffer. A
    /// no-op when empty.
    fn write_buffered(&mut self) -> Result<(), ParquetError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let batch = build_batch(&self.schema, &self.buffer)?;
        if let Some(w) = self.writer.as_mut() {
            w.write(&batch)?;
        }
        self.buffer.clear();
        Ok(())
    }
}

impl<W: Write + Send> FlowExporter for ParquetFlowExporter<W> {
    fn export(&mut self, record: &FlowRecord) {
        self.buffer.push(*record);
        if self.buffer.len() >= self.batch_size
            && let Err(e) = self.write_buffered()
        {
            tracing::warn!(error = %e, "Parquet flow export failed; dropping batch");
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write_buffered()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

impl<W: Write + Send> Drop for ParquetFlowExporter<W> {
    fn drop(&mut self) {
        // Flush any tail rows, then write the Parquet footer (required for the
        // file to be readable). `close` consumes the writer.
        if let Err(e) = self.write_buffered() {
            tracing::warn!(error = %e, "Parquet flush on drop failed");
        }
        if let Some(w) = self.writer.take()
            && let Err(e) = w.close()
        {
            tracing::warn!(error = %e, "Parquet close (footer) on drop failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    use netring::flow::L4Proto;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    fn record(proto: L4Proto, sp: u16, dp: u16, pkts_i: u64) -> FlowRecord {
        FlowRecord {
            proto,
            a: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), sp),
            b: SocketAddr::new(Ipv4Addr::new(203, 0, 113, 7).into(), dp),
            packets_initiator: pkts_i,
            packets_responder: 5,
            bytes_initiator: 1000,
            bytes_responder: 2000,
            start: Timestamp::new(1_700_000_000, 0),
            end: Timestamp::new(1_700_000_005, 250),
            reason: None,
        }
    }

    #[test]
    fn round_trips_flow_rows_through_parquet() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut exporter = ParquetFlowExporter::new(&mut buf).expect("new");
            exporter.export(&record(L4Proto::Tcp, 40000, 443, 9));
            exporter.export(&record(L4Proto::Udp, 5353, 53, 1));
            exporter.flush().expect("flush");
            // drop writes the footer
        }

        // Read it back with the Arrow Parquet reader.
        let bytes = bytes_from(buf);
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .expect("reader builder")
            .build()
            .expect("reader");
        let mut rows = 0usize;
        let mut protos = Vec::new();
        let mut src_ports = Vec::new();
        for batch in reader {
            let batch = batch.expect("batch");
            rows += batch.num_rows();
            let proto_col = batch
                .column_by_name("network.protocol.name")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let port_col = batch
                .column_by_name("source.port")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt16Array>()
                .unwrap();
            for i in 0..batch.num_rows() {
                protos.push(proto_col.value(i).to_string());
                src_ports.push(port_col.value(i));
            }
        }
        assert_eq!(rows, 2);
        assert_eq!(protos, vec!["tcp".to_string(), "udp".to_string()]);
        assert_eq!(src_ports, vec![40000, 5353]);
    }

    #[test]
    fn schema_has_the_expected_flat_columns() {
        let schema = flow_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert!(names.contains(&"network.protocol.name"));
        assert!(names.contains(&"source.address"));
        assert!(names.contains(&"flow.end_reason"));
        // end_reason is the only nullable column.
        let reason = schema.field_with_name("flow.end_reason").unwrap();
        assert!(reason.is_nullable());
        let start = schema.field_with_name("flow.start").unwrap();
        assert!(!start.is_nullable());
    }

    /// `ParquetRecordBatchReaderBuilder::try_new` wants `Bytes` / `ChunkReader`;
    /// wrap the written `Vec<u8>` in `bytes::Bytes`.
    fn bytes_from(v: Vec<u8>) -> bytes::Bytes {
        bytes::Bytes::from(v)
    }
}
