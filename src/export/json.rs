//! JSONL (newline-delimited JSON) writer for packet export.
//!
//! Each packet is serialised as a single JSON object on its own line.
//! The output file uses the `.jsonl` extension by convention.
//!
//! When payload compression is enabled the payload bytes are Zstd-compressed
//! before Base64 encoding, reducing storage for large payloads.

use std::io::{BufWriter, Write};
use std::path::Path;

use base64::Engine as _;
use serde::Serialize;

use crate::error::ExportError;

use super::{PacketRecord, PacketSink};

// ── Serialisable record ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonPacket<'a> {
    timestamp_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_id: Option<u64>,
    caplen: u32,
    origlen: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_flags: Option<u8>,
    /// Raw payload encoded as Base64 (or Base64 of Zstd-compressed bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    /// Present when payload compression is active, to distinguish the encoding.
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_encoding: Option<&'static str>,
}

// ── Streaming sink ────────────────────────────────────────────────────────────

/// Streaming JSONL writer that implements [`PacketSink`].
///
/// Each [`PacketSink::write`] call serialises one packet record immediately
/// without buffering all records in memory first.
pub struct JsonSink {
    out: BufWriter<std::fs::File>,
    compress_payload: bool,
    count: u64,
    b64: base64::engine::general_purpose::GeneralPurpose,
}

impl JsonSink {
    /// Create a new `JsonSink` writing to `path`.
    ///
    /// Uses a 64 KiB write buffer to reduce syscall overhead.
    pub fn create(path: &Path, compress_payload: bool) -> Result<Self, ExportError> {
        let file = std::fs::File::create(path)?;
        Ok(Self {
            out: BufWriter::with_capacity(64 * 1024, file),
            compress_payload,
            count: 0,
            b64: base64::engine::general_purpose::STANDARD,
        })
    }
}

impl PacketSink for JsonSink {
    fn write(&mut self, record: &PacketRecord) -> Result<(), ExportError> {
        let src_ip_str = record.src_ip.map(|ip| ip.to_string());
        let dst_ip_str = record.dst_ip.map(|ip| ip.to_string());

        let payload_encoded = if record.payload.is_empty() {
            None
        } else if self.compress_payload {
            let compressed =
                zstd::encode_all(record.payload.as_slice(), 3).map_err(ExportError::Io)?;
            Some(self.b64.encode(&compressed))
        } else {
            Some(self.b64.encode(&record.payload))
        };

        let encoding = if self.compress_payload && payload_encoded.is_some() {
            Some("zstd+base64")
        } else if payload_encoded.is_some() {
            Some("base64")
        } else {
            None
        };

        let json_rec = JsonPacket {
            timestamp_ns: record.timestamp_ns,
            src_ip: src_ip_str.as_deref(),
            dst_ip: dst_ip_str.as_deref(),
            src_port: record.src_port,
            dst_port: record.dst_port,
            protocol: record.protocol,
            flow_id: record.flow_id,
            caplen: record.caplen,
            origlen: record.origlen,
            tcp_flags: record.tcp_flags,
            payload: payload_encoded,
            payload_encoding: encoding,
        };

        serde_json::to_writer(&mut self.out, &json_rec)
            .map_err(|e| ExportError::Json(e.to_string()))?;
        self.out.write_all(b"\n")?;
        self.count += 1;
        Ok(())
    }

    fn close(&mut self) -> Result<u64, ExportError> {
        self.out.flush()?;
        Ok(self.count)
    }
}
