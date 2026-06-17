use bpaf::{Parser, construct, long};
use std::path::PathBuf;

use crate::cli::{Command, input_arg};

/// Arguments for the `export` subcommand.
#[derive(Debug, Clone)]
pub struct ExportArgs {
    /// Input PCAP / PCAPng file.
    pub input: PathBuf,
    /// Output file path(s). Repeatable for fan-out to multiple formats in one pass.
    pub outputs: Vec<PathBuf>,
    /// Override output format: `json`, `parquet`, or `avro`.
    /// Only applies to the first `--output` when multiple are given.
    pub format: Option<String>,
    /// Compress payload bytes with Zstd (JSON: per-field; Parquet/Avro: column/file codec).
    pub compress_payload: bool,

    // ── Filter flags (same as sort) ────────────────────────────────────────
    /// Comma-separated protocol names or numbers to keep (`tcp,udp,icmp`).
    pub proto: Option<String>,
    /// Source IP addresses or CIDRs to keep. Repeatable; values are OR-ed.
    pub src_ip: Vec<String>,
    /// Destination IP addresses or CIDRs to keep. Repeatable; values are OR-ed.
    pub dst_ip: Vec<String>,
    /// Either-endpoint IP addresses or CIDRs. Repeatable; values are OR-ed.
    pub ip: Vec<String>,
    /// Source port or range. Repeatable; values are OR-ed.
    pub src_port: Vec<String>,
    /// Destination port or range. Repeatable; values are OR-ed.
    pub dst_port: Vec<String>,
    /// Either-endpoint port or range. Repeatable; values are OR-ed.
    pub port: Vec<String>,
    /// Comma-separated hex flow IDs to retain.
    pub flow_id: Option<String>,
    /// Retain only packets at or after this datetime.
    pub from: Option<String>,
    /// Retain only packets at or before this datetime.
    pub to: Option<String>,
    /// TCP flags filter (e.g. `SYN`, `SYN+ACK`, `RST:exact`).
    pub tcp_flags: Option<String>,
    /// Minimum captured packet length in bytes.
    pub min_len: Option<u32>,
    /// Maximum captured packet length in bytes.
    pub max_len: Option<u32>,
    /// Compute flow IDs unidirectionally (default: bidirectional).
    pub unidirectional: bool,
    /// Invert the entire filter result.
    pub negate: bool,
    /// tcpdump/libpcap-style BPF expression.
    pub filter_expr: Option<String>,
    /// Only include flows with at least this many packets.
    pub min_flow_packets: Option<u64>,
}

pub fn export_cmd() -> impl Parser<Command> {
    let input = input_arg();
    let outputs = long("output")
        .short('o')
        .help("Output file path (.jsonl, .parquet, or .avro). Repeatable for fan-out to multiple formats.")
        .argument::<PathBuf>("PATH")
        .many();
    let format = long("format")
        .short('F')
        .help("Override output format: json, parquet, or avro")
        .argument::<String>("FMT")
        .optional();
    let compress_payload = long("compress-payload")
        .help("Compress payload bytes with Zstd")
        .switch();

    // ── Filter flags (shared with sort) ──────────────────────────────────────
    let proto = long("proto")
        .help("Comma-separated protocols to keep: tcp,udp,icmp,icmp6 or numbers")
        .argument::<String>("PROTOS")
        .optional();
    let src_ip = long("src-ip")
        .help("Source IP or CIDR to keep (repeatable, OR-ed)")
        .argument::<String>("CIDR")
        .many();
    let dst_ip = long("dst-ip")
        .help("Destination IP or CIDR to keep (repeatable, OR-ed)")
        .argument::<String>("CIDR")
        .many();
    let ip = long("ip")
        .help("Either-endpoint IP or CIDR (repeatable, OR-ed)")
        .argument::<String>("CIDR")
        .many();
    let src_port = long("src-port")
        .help("Source port or range to keep (repeatable)")
        .argument::<String>("PORT")
        .many();
    let dst_port = long("dst-port")
        .help("Destination port or range to keep (repeatable)")
        .argument::<String>("PORT")
        .many();
    let port = long("port")
        .help("Either-endpoint port or range (repeatable)")
        .argument::<String>("PORT")
        .many();
    let flow_id = long("flow-id")
        .help("Comma-separated hex flow IDs to retain")
        .argument::<String>("IDS")
        .optional();
    let from = long("from")
        .help("Keep packets at or after this datetime (RFC 3339 or Unix epoch seconds)")
        .argument::<String>("DATETIME")
        .optional();
    let to = long("to")
        .help("Keep packets at or before this datetime (RFC 3339 or Unix epoch seconds)")
        .argument::<String>("DATETIME")
        .optional();
    let tcp_flags = long("tcp-flags")
        .help("TCP flags filter, e.g. SYN, SYN+ACK, RST:exact")
        .argument::<String>("FLAGS")
        .optional();
    let min_len = long("min-len")
        .help("Minimum captured packet length in bytes")
        .argument::<u32>("BYTES")
        .optional();
    let max_len = long("max-len")
        .help("Maximum captured packet length in bytes")
        .argument::<u32>("BYTES")
        .optional();
    let unidirectional = long("unidirectional")
        .short('u')
        .help("Compute flow IDs unidirectionally (default: bidirectional)")
        .switch();
    let negate = long("not")
        .help("Invert the filter: keep packets that do NOT match")
        .switch();
    let filter_expr = long("filter")
        .short('f')
        .help("tcpdump/libpcap BPF expression, e.g. \"tcp and dst port 443\"")
        .argument::<String>("EXPR")
        .optional();
    let min_flow_packets = long("min-flow-packets")
        .help("Only include flows with at least N packets (pre-scan pass; non-IP packets excluded)")
        .argument::<u64>("N")
        .optional();

    construct!(ExportArgs {
        compress_payload,
        format,
        outputs,
        proto,
        src_ip,
        dst_ip,
        ip,
        src_port,
        dst_port,
        port,
        flow_id,
        from,
        to,
        tcp_flags,
        min_len,
        max_len,
        unidirectional,
        negate,
        filter_expr,
        min_flow_packets,
        input,
    })
    .to_options()
    .descr("Export PCAP packets to JSON, Parquet, or Avro with optional filtering")
    .command("export")
    .map(|a| Command::Export(Box::new(a)))
}
