//! Apache Avro writer for packet export.
//!
//! Each packet becomes one Avro record. The Avro schema is written to a
//! companion `.avsc` file alongside the data file so the dataset is
//! self-describing.
//!
//! When `compress_payload` is `true` the Avro file uses the Zstd codec,
//! which compresses all data including payload bytes.

use std::path::Path;
use std::sync::LazyLock;

use apache_avro::{Codec, Schema, Writer, ZstandardSettings};
use serde::Serialize;

use crate::error::ExportError;

use super::{PacketRecord, PacketSink};

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
    {"name": "flow_id",      "type": ["null", "long"],     "default": null, "doc": "Deterministic 64-bit flow identifier. Avro has no unsigned 64-bit type, so the u64 bit pattern is stored as a signed long (interpret bitwise to recover the original u64)."},
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

// ── Parsed schema (static, parsed once) ──────────────────────────────────────

static PARSED_SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    Schema::parse_str(AVRO_SCHEMA).expect("built-in Avro schema must parse without error")
});

// ── Streaming sink ────────────────────────────────────────────────────────────

/// Streaming Avro writer that implements [`PacketSink`].
///
/// Each [`PacketSink::write`] call appends one record to the Avro block
/// buffer managed by `apache-avro`. The companion `.avsc` schema file is
/// written during [`AvroSink::create`].
pub struct AvroSink {
    writer: Writer<'static, std::fs::File>,
    count: u64,
}

impl AvroSink {
    /// Create a new `AvroSink` writing to `path`.
    ///
    /// A companion `<path>.avsc` schema file is written immediately.
    pub fn create(path: &Path, compress_payload: bool) -> Result<Self, ExportError> {
        let schema_path = path.with_extension("avsc");
        std::fs::write(&schema_path, AVRO_SCHEMA.trim())?;

        let codec = if compress_payload {
            Codec::Zstandard(ZstandardSettings::new(3))
        } else {
            Codec::Null
        };

        let file = std::fs::File::create(path)?;
        let writer = Writer::with_codec(&PARSED_SCHEMA, file, codec)?;
        Ok(Self { writer, count: 0 })
    }
}

impl PacketSink for AvroSink {
    fn write(&mut self, record: &PacketRecord) -> Result<(), ExportError> {
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
        self.writer
            .append_ser(avro_rec)
            .map_err(ExportError::from)?;
        self.count += 1;
        Ok(())
    }

    fn close(&mut self) -> Result<u64, ExportError> {
        self.writer.flush().map_err(ExportError::from)?;
        Ok(self.count)
    }
}

/// Return a pretty-printed version of the Avro schema (for diagnostics).
pub fn schema_json() -> Result<String, ExportError> {
    let schema = Schema::parse_str(AVRO_SCHEMA).map_err(ExportError::from)?;
    serde_json::to_string_pretty(&schema).map_err(ExportError::from)
}
