//! CLI argument parsing using `bpaf`.

use bpaf::{OptionParser, Parser, construct, long, positional};
use std::path::PathBuf;

/// Top-level parsed CLI arguments.
#[derive(Debug, Clone)]
pub struct Args {
    /// Path to an optional TOML config file.
    pub config: Option<PathBuf>,
    /// The subcommand to execute.
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Clone)]
pub enum Command {
    /// Print a one-line summary of a capture file.
    Info(InfoArgs),
    /// Print per-flow statistics for a capture file.
    Stats(StatsArgs),
    /// Sort a capture chronologically (two-pass indexing).
    Sort(Box<SortArgs>),
}

/// Arguments for the `info` subcommand.
#[derive(Debug, Clone)]
pub struct InfoArgs {
    /// Input PCAP / PCAPng file.
    pub input: PathBuf,
}

/// Arguments for the `stats` subcommand.
#[derive(Debug, Clone)]
pub struct StatsArgs {
    /// Input PCAP / PCAPng file.
    pub input: PathBuf,
    /// Use unidirectional flow IDs (default: bidirectional).
    pub unidirectional: bool,
}

/// Arguments for the `sort` subcommand.
#[derive(Debug, Clone)]
pub struct SortArgs {
    /// Input PCAP file.
    pub input: PathBuf,
    /// Output file path (no slicing) or directory path (with `--slice`).
    pub output: PathBuf,
    /// Time-slice interval, e.g. `1h`, `30m`, `1d`. Omit for a single file.
    pub slice: Option<String>,
    /// Write the packet index to a `.idx` sidecar file instead of keeping it in RAM.
    pub on_disk: bool,

    // ── Filter flags ──────────────────────────────────────────────────────────
    /// Comma-separated protocol names or numbers to keep (`tcp,udp,icmp`).
    pub proto: Option<String>,
    /// Source IP addresses or CIDRs to keep. Repeatable; values are OR-ed.
    pub src_ip: Vec<String>,
    /// Destination IP addresses or CIDRs to keep. Repeatable; values are OR-ed.
    pub dst_ip: Vec<String>,
    /// Either-endpoint IP addresses or CIDRs. Repeatable; values are OR-ed.
    pub ip: Vec<String>,
    /// Source port or range (`443`, `1024-65535`). Repeatable; values are OR-ed.
    pub src_port: Vec<String>,
    /// Destination port or range. Repeatable; values are OR-ed.
    pub dst_port: Vec<String>,
    /// Either-endpoint port or range. Repeatable; values are OR-ed.
    pub port: Vec<String>,
    /// Comma-separated hex flow IDs to retain (e.g. `deadbeef,0xcafe1234`).
    pub flow_id: Option<String>,
    /// Retain only packets at or after this datetime (RFC 3339 or ms epoch).
    pub from: Option<String>,
    /// Retain only packets at or before this datetime (RFC 3339 or ms epoch).
    pub to: Option<String>,
    /// TCP flags filter (e.g. `SYN`, `SYN+ACK`, `RST:exact`).
    pub tcp_flags: Option<String>,
    /// Minimum captured packet length in bytes.
    pub min_len: Option<u32>,
    /// Maximum captured packet length in bytes.
    pub max_len: Option<u32>,
    /// Compute flow IDs unidirectionally (default: bidirectional).
    pub unidirectional: bool,
    /// Invert the entire filter result (keep packets that do NOT match).
    pub negate: bool,
}

fn config_opt() -> impl Parser<Option<PathBuf>> {
    long("config")
        .short('c')
        .help("Path to TOML config file")
        .argument::<PathBuf>("FILE")
        .optional()
}

fn input_arg() -> impl Parser<PathBuf> {
    positional::<PathBuf>("INPUT").help("Input PCAP or PCAPng file")
}

fn info_cmd() -> impl Parser<Command> {
    let input = input_arg();
    construct!(InfoArgs { input })
        .to_options()
        .descr("Print a summary of a PCAP capture (packet count, bytes, IPs, timestamps)")
        .command("info")
        .map(Command::Info)
}

fn stats_cmd() -> impl Parser<Command> {
    let input = input_arg();
    let unidirectional = long("unidirectional")
        .short('u')
        .help("Use unidirectional flow IDs instead of bidirectional")
        .switch();
    construct!(StatsArgs {
        unidirectional,
        input,
    })
    .to_options()
    .descr("Print per-flow statistics keyed by 5-tuple")
    .command("stats")
    .map(Command::Stats)
}

fn sort_cmd() -> impl Parser<Command> {
    let input = input_arg();
    let output = long("output")
        .short('o')
        .help("Output file (no slicing) or directory (with --slice)")
        .argument::<PathBuf>("PATH");
    let slice = long("slice")
        .short('s')
        .help("Split output by time interval, e.g. '1h', '30m', '1d'")
        .argument::<String>("DURATION")
        .optional();
    let on_disk = long("on-disk")
        .help("Store the packet index on disk instead of in RAM")
        .switch();

    // ── Filter flags ─────────────────────────────────────────────────────────
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
        .help("Source port or range to keep, e.g. 443 or 1024-65535 (repeatable)")
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
        .help("Keep packets at or after this datetime (RFC 3339 or ms epoch)")
        .argument::<String>("DATETIME")
        .optional();
    let to = long("to")
        .help("Keep packets at or before this datetime (RFC 3339 or ms epoch)")
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
        .help("Invert the filter: keep packets that do NOT match the filter rules")
        .switch();

    construct!(SortArgs {
        on_disk,
        slice,
        output,
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
        input,
    })
    .to_options()
    .descr("Sort a PCAP capture chronologically using two-pass indexing")
    .command("sort")
    .map(|a| Command::Sort(Box::new(a)))
}

/// Build the top-level argument parser.
pub fn parser() -> OptionParser<Args> {
    let config = config_opt();
    let command = construct!([info_cmd(), stats_cmd(), sort_cmd()]);
    construct!(Args { config, command })
        .to_options()
        .descr("High-performance PCAP inspection, filtering, sorting, and export tool")
        .version(env!("CARGO_PKG_VERSION"))
}
