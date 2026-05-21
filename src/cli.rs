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
    Sort(SortArgs),
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
    construct!(SortArgs {
        on_disk,
        slice,
        output,
        input,
    })
    .to_options()
    .descr("Sort a PCAP capture chronologically using two-pass indexing")
    .command("sort")
    .map(Command::Sort)
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
