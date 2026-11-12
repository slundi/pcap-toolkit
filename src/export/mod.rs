//! Phase 5: Structured data export (JSON, Parquet, Avro).
//!
//! Reads a PCAP file, applies optional filters, and writes each packet as a
//! typed record to the requested format.
//!
//! ## Pipeline (7.3 channel-based)
//!
//! 1. A **producer thread** streams packets from the PCAP file, applies
//!    structured + BPF filters, and sends [`PacketRecord`]s through a bounded
//!    [`std::sync::mpsc::sync_channel`].
//! 2. The **main thread** receives records and writes them to a
//!    format-specific [`PacketSink`] (JSON, Parquet, or Avro).
//!
//! Decoupling I/O (producer) from serialisation (consumer) lets both stages
//! run concurrently, improving throughput for CPU-bound formats.

pub mod avro;
pub mod json;
pub mod parquet;

use std::net::IpAddr;
use std::path::Path;

use crate::bpf::BpfExpr;
use crate::error::ExportError;
use crate::filter::{Filter, PacketMeta};
use crate::pcap::{self, PacketSource};

// ── PacketSink trait ──────────────────────────────────────────────────────────

/// Common interface for streaming packet writers.
///
/// Each format (JSON, Parquet, Avro) provides its own implementation.
/// Records are pushed one at a time via [`write`]; [`close`] flushes any
/// internal buffer and returns the total packet count.
pub trait PacketSink {
    /// Write a single packet record to the output.
    fn write(&mut self, record: &PacketRecord) -> Result<(), ExportError>;

    /// Flush all buffered data and finalise the output file.
    ///
    /// Returns the total number of records written.
    fn close(&mut self) -> Result<u64, ExportError>;
}

/// Channel capacity for the producer → consumer bounded channel.
const CHANNEL_CAPACITY: usize = 4096;

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

/// Destination for a single export target.
#[derive(Debug, Clone)]
pub enum OutputDest {
    /// A file on disk. The extension is used for format auto-detection.
    File(std::path::PathBuf),
    /// Standard output. Only the JSON format is supported (see [`build_sink`]).
    Stdout,
}

impl std::fmt::Display for OutputDest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputDest::File(path) => write!(f, "{}", path.display()),
            OutputDest::Stdout => f.write_str("<stdout>"),
        }
    }
}

/// A single output target for fan-out export.
#[derive(Debug)]
pub struct OutputTarget {
    /// Where the records are written.
    pub dest: OutputDest,
    /// Output format. When `None`, inferred from the file extension (files) or
    /// defaulted to JSON (STDOUT).
    pub format: Option<ExportFormat>,
    /// Apply Zstd compression to payload bytes.
    pub compress_payload: bool,
}

/// Options for [`export_multi`] (fan-out to multiple simultaneous outputs).
#[derive(Debug)]
pub struct MultiExportOptions {
    /// One or more output targets written in a single streaming pass.
    pub targets: Vec<OutputTarget>,
    /// Structured packet filter applied to each packet.
    pub filter: Filter,
    /// BPF expression filter AND-ed with `filter`.
    pub bpf_filter: Option<BpfExpr>,
    /// Compute flow IDs unidirectionally (default: bidirectional).
    pub unidirectional: bool,
}

/// Summary returned by [`export_multi`] on success.
#[derive(Debug)]
pub struct MultiExportReport {
    /// Per-target reports, in the same order as [`MultiExportOptions::targets`].
    pub outputs: Vec<ExportReport>,
}

/// Options for [`export_file`] (single-output convenience wrapper).
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
    /// Total packets written to the output.
    pub packets_written: u64,
    /// Where the records were written.
    pub dest: OutputDest,
}

/// A single packet record ready for serialisation.
#[derive(Debug, Clone)]
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

// ── Public entry points ──────────────────────────────────────────────────────

/// Export packets from `input` to one or more simultaneous outputs in a single
/// streaming pass.
///
/// A bounded channel decouples the PCAP producer thread from the consumer
/// thread that fans each record out to all sinks.  Memory usage is
/// O(channel capacity + per-sink buffer) regardless of capture size.
///
/// # Errors
/// Returns [`ExportError`] on I/O failure, format detection failure, or
/// serialisation error.  If any sink fails mid-stream the producer is signalled
/// to stop and the first error is returned.
pub fn export_multi(
    input: impl Into<PacketSource>,
    opts: &MultiExportOptions,
) -> Result<MultiExportReport, ExportError> {
    let source: PacketSource = input.into();
    if opts.targets.is_empty() {
        return Ok(MultiExportReport {
            outputs: Vec::new(),
        });
    }

    // Build and validate all sinks up front so we fail fast on bad paths/formats.
    struct SinkState {
        sink: Box<dyn PacketSink>,
        dest: OutputDest,
    }
    let mut sinks: Vec<SinkState> = opts
        .targets
        .iter()
        .map(|t| {
            Ok(SinkState {
                sink: build_sink(t)?,
                dest: t.dest.clone(),
            })
        })
        .collect::<Result<Vec<_>, ExportError>>()?;

    let (tx, rx) = std::sync::mpsc::sync_channel::<PacketRecord>(CHANNEL_CAPACITY);

    // Producer: reads PCAP, applies filters, sends PacketRecords.
    let filter = opts.filter.clone();
    let bpf_filter = opts.bpf_filter.clone();
    let unidirectional = opts.unidirectional;

    let producer = std::thread::spawn(move || -> Result<(), ExportError> {
        let has_filter = !filter.is_empty() || bpf_filter.is_some();
        for item in pcap::open_source_with_payload(&source)
            .map_err(|e| ExportError::Parse(e.to_string()))?
        {
            let packet = item.map_err(|e| ExportError::Parse(e.to_string()))?;
            let meta = PacketMeta::from_packet(
                packet.info.timestamp_ns,
                packet.info.captured_len,
                &packet.data,
            );
            if has_filter {
                let ok = (filter.is_empty() || filter.matches(&meta))
                    && bpf_filter.as_ref().is_none_or(|b| b.eval(&meta));
                if !ok {
                    continue;
                }
            }
            let record = build_record(&packet, &meta, unidirectional);
            if tx.send(record).is_err() {
                // Consumer dropped the receiver due to a write error; stop producing.
                break;
            }
        }
        Ok(())
    });

    // Consumer: fan each record out to all sinks.
    for record in rx {
        for state in &mut sinks {
            state.sink.write(&record)?;
        }
    }

    producer.join().map_err(|_| ExportError::ThreadPanic)??;

    // Close all sinks and collect per-output reports.
    let outputs = sinks
        .into_iter()
        .map(|mut state| {
            let packets_written = state.sink.close()?;
            Ok(ExportReport {
                packets_written,
                dest: state.dest,
            })
        })
        .collect::<Result<Vec<_>, ExportError>>()?;

    Ok(MultiExportReport { outputs })
}

/// Export all packets from `input` to a single output (convenience wrapper
/// around [`export_multi`] for backward compatibility).
///
/// # Errors
/// Returns [`ExportError`] on I/O failure, format detection failure, or
/// serialisation error.
pub fn export_file(
    input: impl Into<PacketSource>,
    opts: &ExportOptions,
) -> Result<ExportReport, ExportError> {
    // Resolve format up front so we can return a descriptive error before
    // touching the file system.
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

    let multi_opts = MultiExportOptions {
        targets: vec![OutputTarget {
            dest: OutputDest::File(opts.output.clone()),
            format: Some(format),
            compress_payload: opts.compress_payload,
        }],
        filter: opts.filter.clone(),
        bpf_filter: opts.bpf_filter.clone(),
        unidirectional: opts.unidirectional,
    };
    let mut report = export_multi(input, &multi_opts)?;
    Ok(report.outputs.remove(0))
}

// ── Sink construction ────────────────────────────────────────────────────────

fn build_sink(target: &OutputTarget) -> Result<Box<dyn PacketSink>, ExportError> {
    let path = match &target.dest {
        OutputDest::File(path) => path,
        OutputDest::Stdout => {
            // STDOUT is JSON-only: it is a text stream (Base64-encoded payloads
            // keep it terminal-safe), and parquet/avro need a seekable file plus,
            // for avro, a companion `.avsc` sidecar with no STDOUT equivalent.
            let format = target.format.unwrap_or(ExportFormat::Json);
            if format != ExportFormat::Json {
                return Err(ExportError::StdoutNotJson);
            }
            return Ok(Box::new(json::JsonSink::from_writer(
                std::io::stdout(),
                target.compress_payload,
            )));
        }
    };

    let format = target
        .format
        .or_else(|| ExportFormat::from_extension(path))
        .ok_or_else(|| {
            ExportError::UnknownFormat(
                path.extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("<none>")
                    .to_owned(),
            )
        })?;
    let sink: Box<dyn PacketSink> = match format {
        ExportFormat::Json => Box::new(json::JsonSink::create(path, target.compress_payload)?),
        ExportFormat::Parquet => {
            Box::new(parquet::ParquetSink::create(path, target.compress_payload)?)
        }
        ExportFormat::Avro => Box::new(avro::AvroSink::create(path, target.compress_payload)?),
    };
    Ok(sink)
}

// ── Record construction ───────────────────────────────────────────────────────

fn build_record(
    packet: &pcap::PacketData,
    meta: &PacketMeta,
    unidirectional: bool,
) -> PacketRecord {
    let (src_ip, dst_ip, src_port, dst_port, protocol, flow_id) =
        if let Some(ref key) = meta.flow_key {
            // Ports are only meaningful for TCP (6) and UDP (17); emit None for
            // all other protocols (e.g. ICMP) to avoid misleading zero values.
            let port = matches!(key.protocol, 6 | 17);
            (
                Some(key.src_ip),
                Some(key.dst_ip),
                port.then_some(key.src_port),
                port.then_some(key.dst_port),
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::filter::{PacketMeta, TcpFlagsFilter};
    use crate::flow::FlowKey;
    use crate::pcap::{PacketData, PacketInfo};

    use super::*;

    fn make_packet(caplen: u32) -> PacketData {
        PacketData {
            info: PacketInfo {
                timestamp_ns: 0,
                captured_len: caplen,
                original_len: caplen,
                flow_key: None,
            },
            data: vec![0u8; caplen as usize],
        }
    }

    fn make_meta(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, proto: u8) -> PacketMeta {
        PacketMeta {
            timestamp_ns: 0,
            captured_len: 60,
            flow_key: Some(FlowKey::new(src, dst, sport, dport, proto)),
            tcp_flags: 0,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_build_record_tcp_has_ports() {
        let pkt = make_packet(60);
        let meta = make_meta(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 1234, 443, 6);
        let rec = build_record(&pkt, &meta, false);
        assert_eq!(rec.src_port, Some(1234));
        assert_eq!(rec.dst_port, Some(443));
    }

    #[test]
    fn test_build_record_udp_has_ports() {
        let pkt = make_packet(60);
        let meta = make_meta(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 5000, 53, 17);
        let rec = build_record(&pkt, &meta, false);
        assert_eq!(rec.src_port, Some(5000));
        assert_eq!(rec.dst_port, Some(53));
    }

    #[test]
    fn test_build_record_icmp_ports_are_none() {
        let pkt = make_packet(60);
        // ICMP (protocol 1): FlowKey stores src_port=0/dst_port=0 by convention,
        // but the export record must emit None rather than Some(0).
        let meta = make_meta(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 0, 0, 1);
        let rec = build_record(&pkt, &meta, false);
        assert_eq!(rec.src_port, None, "ICMP src_port must be None");
        assert_eq!(rec.dst_port, None, "ICMP dst_port must be None");
    }

    #[test]
    fn test_build_record_icmpv6_ports_are_none() {
        let pkt = make_packet(60);
        let meta = make_meta(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 0, 0, 58);
        let rec = build_record(&pkt, &meta, false);
        assert_eq!(rec.src_port, None);
        assert_eq!(rec.dst_port, None);
    }

    #[test]
    fn test_build_record_non_ip_all_flow_fields_none() {
        let pkt = make_packet(60);
        let meta = PacketMeta {
            timestamp_ns: 1_000,
            captured_len: 60,
            flow_key: None,
            tcp_flags: 0,
        };
        let rec = build_record(&pkt, &meta, false);
        assert_eq!(rec.src_ip, None);
        assert_eq!(rec.dst_ip, None);
        assert_eq!(rec.src_port, None);
        assert_eq!(rec.dst_port, None);
        assert_eq!(rec.protocol, None);
        assert_eq!(rec.flow_id, None);
        assert_eq!(rec.tcp_flags, None);
    }

    // ── STDOUT export target ──────────────────────────────────────────────────

    #[test]
    fn test_json_sink_to_writer_emits_valid_jsonl() {
        // Exercises the same serialisation path used when streaming to STDOUT,
        // but captures the bytes in an in-memory buffer for assertions.
        let pkt = make_packet(4);
        let meta = make_meta(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 1234, 443, 6);
        let rec = build_record(&pkt, &meta, false);

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut sink = json::JsonSink::from_writer(&mut buf, false);
            sink.write(&rec).unwrap();
            sink.write(&rec).unwrap();
            assert_eq!(sink.close().unwrap(), 2);
        }

        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.lines().count(), 2, "one JSON object per line");
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON per line");
            assert_eq!(v["src_port"], 1234);
            assert_eq!(v["dst_port"], 443);
        }
    }

    #[test]
    fn test_stdout_target_defaults_to_json() {
        // No explicit format on a STDOUT target must resolve to JSON without error.
        let target = OutputTarget {
            dest: OutputDest::Stdout,
            format: None,
            compress_payload: false,
        };
        assert!(build_sink(&target).is_ok());
    }

    #[test]
    fn test_stdout_target_accepts_explicit_json() {
        let target = OutputTarget {
            dest: OutputDest::Stdout,
            format: Some(ExportFormat::Json),
            compress_payload: false,
        };
        assert!(build_sink(&target).is_ok());
    }

    #[test]
    fn test_stdout_target_rejects_parquet() {
        let target = OutputTarget {
            dest: OutputDest::Stdout,
            format: Some(ExportFormat::Parquet),
            compress_payload: false,
        };
        assert!(matches!(
            build_sink(&target),
            Err(ExportError::StdoutNotJson)
        ));
    }

    #[test]
    fn test_stdout_target_rejects_avro() {
        let target = OutputTarget {
            dest: OutputDest::Stdout,
            format: Some(ExportFormat::Avro),
            compress_payload: false,
        };
        assert!(matches!(
            build_sink(&target),
            Err(ExportError::StdoutNotJson)
        ));
    }

    #[test]
    fn test_output_dest_display() {
        assert_eq!(OutputDest::Stdout.to_string(), "<stdout>");
        assert_eq!(
            OutputDest::File(std::path::PathBuf::from("/tmp/out.jsonl")).to_string(),
            "/tmp/out.jsonl"
        );
    }

    #[test]
    fn test_build_record_tcp_flags_only_for_tcp() {
        let pkt = make_packet(60);

        // UDP: tcp_flags must be None even when the meta field is non-zero.
        let mut meta = make_meta(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 100, 200, 17);
        meta.tcp_flags = 0x02; // SYN bit set, but protocol is UDP
        let rec = build_record(&pkt, &meta, false);
        assert_eq!(rec.tcp_flags, None);

        // TCP: tcp_flags must be Some.
        let mut meta = make_meta(v4(1, 2, 3, 4), v4(5, 6, 7, 8), 100, 80, 6);
        meta.tcp_flags = TcpFlagsFilter::parse("SYN+ACK").unwrap().mask;
        let rec = build_record(&pkt, &meta, false);
        assert_eq!(rec.tcp_flags, Some(0x12));
    }
}
