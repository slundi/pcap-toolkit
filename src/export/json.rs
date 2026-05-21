//! JSONL (newline-delimited JSON) writer for packet export.
//!
//! Each packet is serialised as a single JSON object on its own line.
//! The output file uses the `.jsonl` extension by convention.
//!
//! When payload compression is enabled the payload bytes are Zstd-compressed
//! before Base64 encoding, reducing storage for large payloads.

use std::io::{BufWriter, Write};

use base64::Engine as _;
use serde::Serialize;

use crate::error::ExportError;

use super::PacketRecord;

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
    flow_id: Option<String>,
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

// ── Writer ────────────────────────────────────────────────────────────────────

/// Write `records` to `path` as JSONL (one JSON object per line).
///
/// When `compress_payload` is `true` each payload is Zstd-compressed before
/// Base64 encoding and the field `payload_encoding` is set to `"zstd+base64"`.
pub fn write_jsonl(
    path: &std::path::Path,
    records: &[PacketRecord],
    compress_payload: bool,
) -> Result<usize, ExportError> {
    let file = std::fs::File::create(path)?;
    let mut out = BufWriter::new(file);
    let b64 = base64::engine::general_purpose::STANDARD;

    let src_ip_strs: Vec<Option<String>> = records
        .iter()
        .map(|r| r.src_ip.map(|ip| ip.to_string()))
        .collect();
    let dst_ip_strs: Vec<Option<String>> = records
        .iter()
        .map(|r| r.dst_ip.map(|ip| ip.to_string()))
        .collect();

    for (i, record) in records.iter().enumerate() {
        let payload_encoded = if record.payload.is_empty() {
            None
        } else if compress_payload {
            let compressed =
                zstd::encode_all(record.payload.as_slice(), 3).map_err(ExportError::Io)?;
            Some(b64.encode(&compressed))
        } else {
            Some(b64.encode(&record.payload))
        };

        let encoding = if compress_payload && payload_encoded.is_some() {
            Some("zstd+base64")
        } else if payload_encoded.is_some() {
            Some("base64")
        } else {
            None
        };

        let json_rec = JsonPacket {
            timestamp_ns: record.timestamp_ns,
            src_ip: src_ip_strs[i].as_deref(),
            dst_ip: dst_ip_strs[i].as_deref(),
            src_port: record.src_port,
            dst_port: record.dst_port,
            protocol: record.protocol,
            flow_id: record.flow_id.map(|id| format!("{id:016x}")),
            caplen: record.caplen,
            origlen: record.origlen,
            tcp_flags: record.tcp_flags,
            payload: payload_encoded,
            payload_encoding: encoding,
        };

        serde_json::to_writer(&mut out, &json_rec).map_err(|e| ExportError::Json(e.to_string()))?;
        out.write_all(b"\n")?;
    }

    out.flush()?;
    Ok(records.len())
}
