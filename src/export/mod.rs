//! Phase 5: Structured data export (JSON, Parquet, Avro).
//!
//! Reads a PCAP file, applies optional filters, and writes each packet as a
//! typed record to the requested format.
//!
//! ## Pipeline
//!
//! 1. Stream packets from the PCAP file via [`crate::pcap::open_with_payload`].
//! 2. For each packet, build a [`PacketMeta`] and apply structured + BPF
//!    filters (same logic as the sort second pass).
//! 3. Construct a [`PacketRecord`] with all parsed layer fields.
//! 4. Accumulate records and dispatch to the format-specific writer.

pub mod avro;
pub mod json;
pub mod parquet;

use std::net::IpAddr;
use std::path::Path;

use crate::bpf::BpfExpr;
use crate::error::ExportError;
use crate::filter::{Filter, PacketMeta};
use crate::pcap;

// ── Public types ─────────────────────────────────────────────────────────────

/// Output format for packet export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Newline-delimited JSON (`.jsonl`).
    Json,
    /// Apache Parquet columnar format (`.parquet`).
    Parquet,
    /// Apache Avro record format (`.avro`).
    Avro,
}

impl ExportFormat {
    /// Infer the format from a file extension, returning `None` if unknown.
    pub fn from_extension(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "jsonl" | "json" | "ndjson" => Some(Self::Json),
            "parquet" => Some(Self::Parquet),
            "avro" => Some(Self::Avro),
            _ => None,
        }
    }

    /// Parse from a user-supplied string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "json" | "jsonl" | "ndjson" => Some(Self::Json),
            "parquet" => Some(Self::Parquet),
            "avro" => Some(Self::Avro),
            _ => None,
        }
    }
}

/// Options for [`export_file`].
#[derive(Debug, Default)]
pub struct ExportOptions {
    /// Destination file path (extension used for format auto-detection).
    pub output: std::path::PathBuf,
    /// Output format. When `None`, inferred from the output file extension.
    pub format: Option<ExportFormat>,
    /// Apply Zstd compression to payload bytes (JSON: per-payload field;
    /// Parquet: column-level compression; Avro: file-level codec).
    pub compress_payload: bool,
    /// Structured packet filter applied to each packet.
    pub filter: Filter,
    /// BPF expression filter AND-ed with `filter`.
    pub bpf_filter: Option<BpfExpr>,
    /// Compute flow IDs unidirectionally (default: bidirectional).
    pub unidirectional: bool,
}

/// Summary returned by [`export_file`] on success.
#[derive(Debug)]
pub struct ExportReport {
    /// Total packets written to the output file.
    pub packets_written: u64,
    /// Path of the output file.
    pub output_path: std::path::PathBuf,
}

/// A single packet record ready for serialisation.
#[derive(Debug)]
pub struct PacketRecord {
    /// Timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Source IP address (IPv4 or IPv6), if available.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address, if available.
    pub dst_ip: Option<IpAddr>,
    /// Source port (TCP/UDP only).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP only).
    pub dst_port: Option<u16>,
    /// IP protocol number (6=TCP, 17=UDP, …).
    pub protocol: Option<u8>,
    /// Deterministic 64-bit flow ID.
    pub flow_id: Option<u64>,
    /// Captured packet length (bytes stored in the file).
    pub caplen: u32,
    /// Original wire length.
    pub origlen: u32,
    /// TCP control-flags bitmask; `None` for non-TCP traffic.
    pub tcp_flags: Option<u8>,
    /// Raw captured bytes (Ethernet frame payload up to snap length).
    pub payload: Vec<u8>,
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Export all packets from `input` to the format specified in `opts`.
///
/// # Errors
/// Returns [`ExportError`] on I/O failure, format detection failure, or
/// serialisation error.
pub fn export_file(input: &Path, opts: &ExportOptions) -> Result<ExportReport, ExportError> {
    let format = opts
        .format
        .or_else(|| ExportFormat::from_extension(&opts.output))
        .ok_or_else(|| {
            ExportError::UnknownFormat(
                opts.output
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("<none>")
                    .to_owned(),
            )
        })?;

    let has_filter = !opts.filter.is_empty() || opts.bpf_filter.is_some();

    let mut records: Vec<PacketRecord> = Vec::new();

    for item in pcap::open_with_payload(input).map_err(|e| ExportError::Parse(e.to_string()))? {
        let packet = item.map_err(|e| ExportError::Parse(e.to_string()))?;

        let meta = PacketMeta::from_packet(
            packet.info.timestamp_ns,
            packet.info.captured_len,
            &packet.data,
        );

        if has_filter {
            let structured_pass = opts.filter.is_empty() || opts.filter.matches(&meta);
            let bpf_pass = opts
                .bpf_filter
                .as_ref()
                .map(|b| b.eval(&meta))
                .unwrap_or(true);
            if !structured_pass || !bpf_pass {
                continue;
            }
        }

        records.push(build_record(&packet, &meta, opts.unidirectional));
    }

    let count = records.len();

    match format {
        ExportFormat::Json => {
            json::write_jsonl(&opts.output, &records, opts.compress_payload)?;
        }
        ExportFormat::Parquet => {
            parquet::write_parquet(&opts.output, &records, opts.compress_payload)?;
        }
        ExportFormat::Avro => {
            avro::write_avro(&opts.output, &records, opts.compress_payload)?;
        }
    }

    Ok(ExportReport {
        packets_written: count as u64,
        output_path: opts.output.clone(),
    })
}

// ── Record construction ───────────────────────────────────────────────────────

fn build_record(
    packet: &pcap::PacketData,
    meta: &PacketMeta,
    unidirectional: bool,
) -> PacketRecord {
    let (src_ip, dst_ip, src_port, dst_port, protocol, flow_id) =
        if let Some(ref key) = meta.flow_key {
            (
                Some(key.src_ip),
                Some(key.dst_ip),
                Some(key.src_port),
                Some(key.dst_port),
                Some(key.protocol),
                Some(key.flow_id(unidirectional)),
            )
        } else {
            (None, None, None, None, None, None)
        };

    // Report tcp_flags only for TCP packets.
    let tcp_flags = if meta.flow_key.as_ref().is_some_and(|k| k.protocol == 6) {
        Some(meta.tcp_flags)
    } else {
        None
    };

    PacketRecord {
        timestamp_ns: meta.timestamp_ns,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        flow_id,
        caplen: packet.info.captured_len,
        origlen: packet.info.original_len,
        tcp_flags,
        payload: packet.data.clone(),
    }
}
