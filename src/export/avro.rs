//! Apache Avro writer for packet export.
//!
//! Each packet becomes one Avro record. The Avro schema is written to a
//! companion `.avsc` file alongside the data file so the dataset is
//! self-describing.
//!
//! When `compress_payload` is `true` the Avro file uses the Zstd codec,
//! which compresses all data including payload bytes.

use std::path::Path;

use apache_avro::{Codec, Schema, Writer, ZstandardSettings};
use serde::Serialize;

use crate::error::ExportError;

use super::PacketRecord;

// ── Avro schema ───────────────────────────────────────────────────────────────

/// Avro schema definition — kept in sync with [`AvroPacket`].
pub const AVRO_SCHEMA: &str = r#"
{
  "type": "record",
  "name": "Packet",
  "namespace": "pcap_toolkit",
  "doc": "A single captured network packet with parsed layer fields.",
  "fields": [
    {"name": "timestamp_ns", "type": "long",               "doc": "Capture timestamp, nanoseconds since Unix epoch."},
    {"name": "src_ip",       "type": ["null", "string"],   "default": null, "doc": "Source IP address (IPv4 or IPv6 string)."},
    {"name": "dst_ip",       "type": ["null", "string"],   "default": null, "doc": "Destination IP address."},
    {"name": "src_port",     "type": ["null", "int"],      "default": null, "doc": "Source port (TCP/UDP only)."},
    {"name": "dst_port",     "type": ["null", "int"],      "default": null, "doc": "Destination port (TCP/UDP only)."},
    {"name": "protocol",     "type": ["null", "int"],      "default": null, "doc": "IP protocol number (6=TCP, 17=UDP, …)."},
    {"name": "flow_id",      "type": ["null", "long"],     "default": null, "doc": "Deterministic 64-bit flow identifier."},
    {"name": "caplen",       "type": "int",                                 "doc": "Captured bytes (wire length may differ)."},
    {"name": "origlen",      "type": "int",                                 "doc": "Original wire length."},
    {"name": "tcp_flags",    "type": ["null", "int"],      "default": null, "doc": "TCP control flags bitmask."},
    {"name": "payload",      "type": ["null", "bytes"],    "default": null, "doc": "Raw captured payload bytes."}
  ]
}
"#;

// ── Serialisable record ───────────────────────────────────────────────────────

/// Serde-serialisable representation of one packet for `apache-avro`.
///
/// Field types match the Avro schema above.  `apache-avro` maps `Option<T>`
/// to `["null", T]` unions automatically.
#[derive(Serialize)]
struct AvroPacket {
    timestamp_ns: i64,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    protocol: Option<i32>,
    flow_id: Option<i64>,
    caplen: i32,
    origlen: i32,
    tcp_flags: Option<i32>,
    payload: Option<serde_bytes::ByteBuf>,
}

// ── Writer ────────────────────────────────────────────────────────────────────

/// Write `records` to an Avro data file at `path`.
///
/// A companion schema file (`<path>.avsc`) is written alongside the data.
/// When `compress_payload` is `true` the Avro file uses the Zstd codec.
pub fn write_avro(
    path: &Path,
    records: &[PacketRecord],
    compress_payload: bool,
) -> Result<usize, ExportError> {
    // Write the schema file.
    let schema_path = path.with_extension("avsc");
    std::fs::write(&schema_path, AVRO_SCHEMA.trim())?;

    let schema = Schema::parse_str(AVRO_SCHEMA).map_err(|e| ExportError::Avro(e.to_string()))?;

    let codec = if compress_payload {
        Codec::Zstandard(ZstandardSettings::new(3))
    } else {
        Codec::Null
    };

    let file = std::fs::File::create(path)?;
    let mut writer = Writer::with_codec(&schema, file, codec);

    for record in records {
        let avro_rec = AvroPacket {
            timestamp_ns: record.timestamp_ns as i64,
            src_ip: record.src_ip.map(|ip| ip.to_string()),
            dst_ip: record.dst_ip.map(|ip| ip.to_string()),
            src_port: record.src_port.map(|p| p as i32),
            dst_port: record.dst_port.map(|p| p as i32),
            protocol: record.protocol.map(|p| p as i32),
            flow_id: record.flow_id.map(|id| id as i64),
            caplen: record.caplen as i32,
            origlen: record.origlen as i32,
            tcp_flags: record.tcp_flags.map(|f| f as i32),
            payload: if record.payload.is_empty() {
                None
            } else {
                Some(serde_bytes::ByteBuf::from(record.payload.clone()))
            },
        };
        writer
            .append_ser(avro_rec)
            .map_err(|e| ExportError::Avro(e.to_string()))?;
    }

    writer
        .flush()
        .map_err(|e| ExportError::Avro(e.to_string()))?;

    Ok(records.len())
}

/// Return a pretty-printed version of the Avro schema (for diagnostics).
pub fn schema_json() -> Result<String, ExportError> {
    let schema = Schema::parse_str(AVRO_SCHEMA).map_err(|e| ExportError::Avro(e.to_string()))?;
    serde_json::to_string_pretty(&schema).map_err(|e| ExportError::Avro(e.to_string()))
}
