//! Apache Parquet columnar writer for packet export.
//!
//! Uses the `parquet` crate's column-writer API to produce typed, columnar
//! Parquet files without requiring the Arrow library.
//!
//! Schema
//! ------
//! ```text
//! message schema {
//!   REQUIRED INT64  timestamp_ns;
//!   OPTIONAL BINARY src_ip      (STRING);
//!   OPTIONAL BINARY dst_ip      (STRING);
//!   OPTIONAL INT32  src_port;
//!   OPTIONAL INT32  dst_port;
//!   OPTIONAL INT32  protocol;
//!   OPTIONAL INT64  flow_id;
//!   REQUIRED INT32  caplen;
//!   REQUIRED INT32  origlen;
//!   OPTIONAL INT32  tcp_flags;
//!   OPTIONAL BINARY payload;
//! }
//! ```
//!
//! Row groups contain up to [`BATCH_SIZE`] rows. When `compress_payload` is
//! `true` ZSTD compression is applied to all columns (Parquet has no
//! per-field compression; ZSTD on a binary column containing payloads yields
//! the largest savings).

use std::path::Path;
use std::sync::Arc;

use parquet::basic::{Compression, Repetition, ZstdLevel};
use parquet::column::writer::ColumnWriter;
use parquet::data_type::ByteArray;
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use parquet::schema::types::Type;

use crate::error::ExportError;

use super::{PacketRecord, PacketSink};

/// Number of packets per Parquet row group.
const BATCH_SIZE: usize = 4096;

const SCHEMA_STR: &str = "
message schema {
  REQUIRED INT64  timestamp_ns;
  OPTIONAL BYTE_ARRAY src_ip      (STRING);
  OPTIONAL BYTE_ARRAY dst_ip      (STRING);
  OPTIONAL INT32  src_port;
  OPTIONAL INT32  dst_port;
  OPTIONAL INT32  protocol;
  OPTIONAL INT64  flow_id;
  REQUIRED INT32  caplen;
  REQUIRED INT32  origlen;
  OPTIONAL INT32  tcp_flags;
  OPTIONAL BYTE_ARRAY payload;
}
";

// ── Streaming sink ────────────────────────────────────────────────────────────

/// Streaming Parquet writer that implements [`PacketSink`].
///
/// Records are accumulated into an internal buffer; a row group is flushed
/// every [`BATCH_SIZE`] records. The remaining records are flushed on
/// [`PacketSink::close`].
pub struct ParquetSink {
    writer: Option<SerializedFileWriter<std::fs::File>>,
    buffer: Vec<PacketRecord>,
    count: u64,
}

impl ParquetSink {
    /// Create a new `ParquetSink` writing to `path`.
    pub fn create(path: &Path, compress_payload: bool) -> Result<Self, ExportError> {
        let schema: Arc<Type> = Arc::new(
            parse_message_type(SCHEMA_STR).map_err(|e| ExportError::Parquet(e.to_string()))?,
        );
        let compression = if compress_payload {
            Compression::ZSTD(
                ZstdLevel::try_new(3).map_err(|e| ExportError::Parquet(e.to_string()))?,
            )
        } else {
            Compression::SNAPPY
        };
        let props = Arc::new(
            WriterProperties::builder()
                .set_compression(compression)
                .build(),
        );
        let file = std::fs::File::create(path)?;
        let writer = SerializedFileWriter::new(file, schema, props)
            .map_err(|e| ExportError::Parquet(e.to_string()))?;
        Ok(Self {
            writer: Some(writer),
            buffer: Vec::with_capacity(BATCH_SIZE),
            count: 0,
        })
    }
}

impl PacketSink for ParquetSink {
    fn write(&mut self, record: PacketRecord) -> Result<(), ExportError> {
        self.buffer.push(record);
        self.count += 1;
        if self.buffer.len() >= BATCH_SIZE {
            let batch = std::mem::take(&mut self.buffer);
            if let Some(ref mut w) = self.writer {
                write_row_group(w, &batch)?;
            }
        }
        Ok(())
    }

    fn close(&mut self) -> Result<u64, ExportError> {
        if !self.buffer.is_empty() {
            let batch = std::mem::take(&mut self.buffer);
            if let Some(ref mut w) = self.writer {
                write_row_group(w, &batch)?;
            }
        }
        if let Some(writer) = self.writer.take() {
            writer
                .close()
                .map_err(|e| ExportError::Parquet(e.to_string()))?;
        }
        Ok(self.count)
    }
}

/// Write one row group from a slice of records.
fn write_row_group(
    writer: &mut SerializedFileWriter<std::fs::File>,
    chunk: &[PacketRecord],
) -> Result<(), ExportError> {
    let mut rg = writer
        .next_row_group()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;

    // ── timestamp_ns (REQUIRED INT64) ────────────────────────────────────────
    {
        let values: Vec<i64> = chunk.iter().map(|r| r.timestamp_ns as i64).collect();
        write_required_i64(&mut rg, &values)?;
    }

    // ── src_ip (OPTIONAL BYTE_ARRAY / STRING) ────────────────────────────────
    {
        let strings: Vec<Option<String>> = chunk
            .iter()
            .map(|r| r.src_ip.map(|ip| ip.to_string()))
            .collect();
        write_optional_bytes(&mut rg, &strings)?;
    }

    // ── dst_ip ───────────────────────────────────────────────────────────────
    {
        let strings: Vec<Option<String>> = chunk
            .iter()
            .map(|r| r.dst_ip.map(|ip| ip.to_string()))
            .collect();
        write_optional_bytes(&mut rg, &strings)?;
    }

    // ── src_port (OPTIONAL INT32) ────────────────────────────────────────────
    {
        let values: Vec<Option<i32>> = chunk.iter().map(|r| r.src_port.map(|p| p as i32)).collect();
        write_optional_i32(&mut rg, &values)?;
    }

    // ── dst_port ─────────────────────────────────────────────────────────────
    {
        let values: Vec<Option<i32>> = chunk.iter().map(|r| r.dst_port.map(|p| p as i32)).collect();
        write_optional_i32(&mut rg, &values)?;
    }

    // ── protocol ─────────────────────────────────────────────────────────────
    {
        let values: Vec<Option<i32>> = chunk.iter().map(|r| r.protocol.map(|p| p as i32)).collect();
        write_optional_i32(&mut rg, &values)?;
    }

    // ── flow_id (OPTIONAL INT64) ─────────────────────────────────────────────
    {
        let values: Vec<Option<i64>> = chunk
            .iter()
            .map(|r| r.flow_id.map(|id| id as i64))
            .collect();
        write_optional_i64(&mut rg, &values)?;
    }

    // ── caplen (REQUIRED INT32) ──────────────────────────────────────────────
    {
        let values: Vec<i32> = chunk.iter().map(|r| r.caplen as i32).collect();
        write_required_i32(&mut rg, &values)?;
    }

    // ── origlen (REQUIRED INT32) ─────────────────────────────────────────────
    {
        let values: Vec<i32> = chunk.iter().map(|r| r.origlen as i32).collect();
        write_required_i32(&mut rg, &values)?;
    }

    // ── tcp_flags (OPTIONAL INT32) ───────────────────────────────────────────
    {
        let values: Vec<Option<i32>> = chunk
            .iter()
            .map(|r| r.tcp_flags.map(|f| f as i32))
            .collect();
        write_optional_i32(&mut rg, &values)?;
    }

    // ── payload (OPTIONAL BYTE_ARRAY) ────────────────────────────────────────
    {
        let payloads: Vec<Option<&[u8]>> = chunk
            .iter()
            .map(|r| {
                if r.payload.is_empty() {
                    None
                } else {
                    Some(r.payload.as_slice())
                }
            })
            .collect();
        write_optional_binary(&mut rg, &payloads)?;
    }

    rg.close()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;
    Ok(())
}

// ── Column helpers ────────────────────────────────────────────────────────────

fn write_required_i64(
    rg: &mut parquet::file::writer::SerializedRowGroupWriter<std::fs::File>,
    values: &[i64],
) -> Result<(), ExportError> {
    let mut col = rg
        .next_column()
        .map_err(|e| ExportError::Parquet(e.to_string()))?
        .expect("column count mismatch");
    match col.untyped() {
        ColumnWriter::Int64ColumnWriter(w) => {
            w.write_batch(values, None, None)
                .map_err(|e| ExportError::Parquet(e.to_string()))?;
        }
        _ => return Err(ExportError::Parquet("expected INT64 column".into())),
    }
    col.close()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;
    Ok(())
}

fn write_required_i32(
    rg: &mut parquet::file::writer::SerializedRowGroupWriter<std::fs::File>,
    values: &[i32],
) -> Result<(), ExportError> {
    let mut col = rg
        .next_column()
        .map_err(|e| ExportError::Parquet(e.to_string()))?
        .expect("column count mismatch");
    match col.untyped() {
        ColumnWriter::Int32ColumnWriter(w) => {
            w.write_batch(values, None, None)
                .map_err(|e| ExportError::Parquet(e.to_string()))?;
        }
        _ => return Err(ExportError::Parquet("expected INT32 column".into())),
    }
    col.close()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;
    Ok(())
}

fn write_optional_i32(
    rg: &mut parquet::file::writer::SerializedRowGroupWriter<std::fs::File>,
    values: &[Option<i32>],
) -> Result<(), ExportError> {
    let non_null: Vec<i32> = values.iter().filter_map(|v| *v).collect();
    let def_levels: Vec<i16> = values
        .iter()
        .map(|v| if v.is_some() { 1 } else { 0 })
        .collect();

    let mut col = rg
        .next_column()
        .map_err(|e| ExportError::Parquet(e.to_string()))?
        .expect("column count mismatch");
    match col.untyped() {
        ColumnWriter::Int32ColumnWriter(w) => {
            w.write_batch(&non_null, Some(&def_levels), None)
                .map_err(|e| ExportError::Parquet(e.to_string()))?;
        }
        _ => return Err(ExportError::Parquet("expected INT32 column".into())),
    }
    col.close()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;
    Ok(())
}

fn write_optional_i64(
    rg: &mut parquet::file::writer::SerializedRowGroupWriter<std::fs::File>,
    values: &[Option<i64>],
) -> Result<(), ExportError> {
    let non_null: Vec<i64> = values.iter().filter_map(|v| *v).collect();
    let def_levels: Vec<i16> = values
        .iter()
        .map(|v| if v.is_some() { 1 } else { 0 })
        .collect();

    let mut col = rg
        .next_column()
        .map_err(|e| ExportError::Parquet(e.to_string()))?
        .expect("column count mismatch");
    match col.untyped() {
        ColumnWriter::Int64ColumnWriter(w) => {
            w.write_batch(&non_null, Some(&def_levels), None)
                .map_err(|e| ExportError::Parquet(e.to_string()))?;
        }
        _ => return Err(ExportError::Parquet("expected INT64 column".into())),
    }
    col.close()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;
    Ok(())
}

fn write_optional_bytes(
    rg: &mut parquet::file::writer::SerializedRowGroupWriter<std::fs::File>,
    values: &[Option<String>],
) -> Result<(), ExportError> {
    let non_null: Vec<ByteArray> = values
        .iter()
        .filter_map(|v| v.as_deref())
        .map(|s| ByteArray::from(s.as_bytes().to_vec()))
        .collect();
    let def_levels: Vec<i16> = values
        .iter()
        .map(|v| if v.is_some() { 1 } else { 0 })
        .collect();

    let mut col = rg
        .next_column()
        .map_err(|e| ExportError::Parquet(e.to_string()))?
        .expect("column count mismatch");
    match col.untyped() {
        ColumnWriter::ByteArrayColumnWriter(w) => {
            w.write_batch(&non_null, Some(&def_levels), None)
                .map_err(|e| ExportError::Parquet(e.to_string()))?;
        }
        _ => return Err(ExportError::Parquet("expected BYTE_ARRAY column".into())),
    }
    col.close()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;
    Ok(())
}

fn write_optional_binary(
    rg: &mut parquet::file::writer::SerializedRowGroupWriter<std::fs::File>,
    values: &[Option<&[u8]>],
) -> Result<(), ExportError> {
    let non_null: Vec<ByteArray> = values
        .iter()
        .filter_map(|v| *v)
        .map(|b| ByteArray::from(b.to_vec()))
        .collect();
    let def_levels: Vec<i16> = values
        .iter()
        .map(|v| if v.is_some() { 1 } else { 0 })
        .collect();

    let mut col = rg
        .next_column()
        .map_err(|e| ExportError::Parquet(e.to_string()))?
        .expect("column count mismatch");
    match col.untyped() {
        ColumnWriter::ByteArrayColumnWriter(w) => {
            w.write_batch(&non_null, Some(&def_levels), None)
                .map_err(|e| ExportError::Parquet(e.to_string()))?;
        }
        _ => return Err(ExportError::Parquet("expected BYTE_ARRAY column".into())),
    }
    col.close()
        .map_err(|e| ExportError::Parquet(e.to_string()))?;
    Ok(())
}

/// Check which physical type the schema assigns to each column index.
/// Used only for sanity testing; not called in production.
pub fn column_repetitions() -> Vec<(usize, Repetition)> {
    let schema = parse_message_type(SCHEMA_STR).unwrap();
    schema
        .get_fields()
        .iter()
        .enumerate()
        .map(|(i, f)| (i, f.get_basic_info().repetition()))
        .collect()
}
