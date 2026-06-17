//! Binary entry point for pcap-toolkit.

mod cli;

use anyhow::{Context, Result};
use pcap_toolkit::{
    bpf,
    config::{Config, TransformConfig},
    export::{self, ExportFormat, MultiExportOptions, OutputTarget},
    filter::{
        Filter, IpNet, PortRange, TcpFlagsFilter, parse_datetime_ns, parse_flow_ids,
        parse_proto_list,
    },
    pcap,
    replay::{self, ReplayOptions, ReplaySpeed},
    sort::{self, SortOptions},
    stats::{CaptureInfo, StatsCollector},
    transform::{ProtocolTruncation, TransformOptions, parse_ip_mapping},
};
use rustc_hash::FxHashSet;

fn main() -> Result<()> {
    let args = cli::parser().run();

    // Load optional config file.
    let config = match &args.config {
        Some(path) => Config::from_file(path)
            .with_context(|| format!("failed to load config from {}", path.display()))?,
        None => Config::default(),
    };

    match args.command {
        cli::Command::Info(a) => cmd_info(&a),
        cli::Command::Stats(a) => cmd_stats(&a),
        cli::Command::Sort(a) => cmd_sort(&a, &config),
        cli::Command::Export(a) => cmd_export(&a, &config),
        cli::Command::Replay(a) => cmd_replay(&a),
    }
}

fn cmd_info(args: &cli::InfoArgs) -> Result<()> {
    let info = collect_info(&args.input, false)?;
    print_info(&info);
    Ok(())
}

fn cmd_stats(args: &cli::StatsArgs) -> Result<()> {
    let info = collect_info(&args.input, args.unidirectional)?;
    print_info(&info);
    print_flows(&info);
    Ok(())
}

fn collect_info(path: &std::path::Path, unidirectional: bool) -> Result<CaptureInfo> {
    let mut collector = StatsCollector::new(unidirectional);
    let iter = pcap::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    for result in iter {
        let pkt = result.with_context(|| format!("error reading {}", path.display()))?;
        collector.feed(pkt.timestamp_ns, pkt.captured_len, pkt.flow_key);
    }

    Ok(collector.finish())
}

fn print_info(info: &CaptureInfo) {
    println!("Packets : {}", info.total_packets);
    println!("Bytes   : {}", info.total_bytes);
    println!(
        "Start   : {}",
        info.start
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "—".to_string())
    );
    println!(
        "End     : {}",
        info.end
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "—".to_string())
    );
    println!(
        "Duration: {}",
        info.duration()
            .map(format_duration)
            .unwrap_or_else(|| "—".to_string())
    );
    println!("Src IPs : {}", info.unique_src_ips.len());
    println!("Dst IPs : {}", info.unique_dst_ips.len());
    println!("Flows   : {}", info.flow_count());
}

fn print_flows(info: &CaptureInfo) {
    if info.flows.is_empty() {
        return;
    }
    println!();
    println!(
        "{:<20} {:<20} {:<8} {:<8} {:<5} {:>10} {:>12} {:>18}",
        "Src IP", "Dst IP", "SrcPort", "DstPort", "Proto", "Packets", "Bytes", "Flow ID"
    );
    println!("{}", "-".repeat(105));

    let mut flows = info.flows.clone();
    flows.sort_by_key(|f| std::cmp::Reverse(f.bytes));

    for f in &flows {
        println!(
            "{:<20} {:<20} {:<8} {:<8} {:<5} {:>10} {:>12} {:>18x}",
            f.key.src_ip.to_string(),
            f.key.dst_ip.to_string(),
            f.key.src_port,
            f.key.dst_port,
            f.key.protocol,
            f.packets,
            f.bytes,
            f.flow_id,
        );
    }
}

fn cmd_sort(args: &cli::SortArgs, config: &Config) -> Result<()> {
    if args.inputs.is_empty() {
        anyhow::bail!("sort requires at least one input file");
    }

    let slice_secs = args
        .slice
        .as_deref()
        .map(sort::parse_slice)
        .transpose()
        .with_context(|| "invalid --slice value")?;

    let filter = build_filter(args)?;

    let bpf_filter = args
        .filter_expr
        .as_deref()
        .map(|expr| {
            bpf::parse(expr).with_context(|| format!("invalid --filter expression '{expr}'"))
        })
        .transpose()?;

    let transform = build_transform(args, &config.transform)?;

    // CLI --min-flow-packets takes precedence over TOML config value.
    let min_flow_packets = args.min_flow_packets.or(config.filter.min_flow_packets);
    let input_paths: Vec<&std::path::Path> = args.inputs.iter().map(|p| p.as_path()).collect();
    let filter = if let Some(min_pkts) = min_flow_packets {
        resolve_min_flow_filter(&input_paths, &filter, bpf_filter.as_ref(), min_pkts)?
    } else {
        filter
    };

    let opts = SortOptions {
        output: args.output.clone(),
        slice_secs,
        on_disk: args.on_disk,
        filter,
        bpf_filter,
        transform,
    };

    let report =
        sort::sort_files(&input_paths, &opts).with_context(|| "failed to sort input file(s)")?;

    println!(
        "Sorted {} packet(s) into {} file(s):",
        report.packets_written,
        report.files_written.len()
    );
    for f in &report.files_written {
        println!("  {}", f.display());
    }
    Ok(())
}

/// Construct a [`Filter`] from the CLI arguments on the `sort` subcommand.
fn build_filter(args: &cli::SortArgs) -> Result<Filter> {
    let mut f = Filter {
        unidirectional: args.unidirectional,
        negate: args.negate,
        ..Filter::default()
    };

    if let Some(proto_str) = &args.proto {
        f.protocols = parse_proto_list(proto_str)
            .with_context(|| format!("invalid --proto value '{proto_str}'"))?;
    }

    for s in &args.src_ip {
        f.src_ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --src-ip value '{s}'"))?);
    }
    for s in &args.dst_ip {
        f.dst_ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --dst-ip value '{s}'"))?);
    }
    for s in &args.ip {
        f.ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --ip value '{s}'"))?);
    }

    for s in &args.src_port {
        f.src_ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --src-port value '{s}'"))?);
    }
    for s in &args.dst_port {
        f.dst_ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --dst-port value '{s}'"))?);
    }
    for s in &args.port {
        f.ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --port value '{s}'"))?);
    }

    if let Some(ids_str) = &args.flow_id {
        f.flow_ids = parse_flow_ids(ids_str)
            .with_context(|| format!("invalid --flow-id value '{ids_str}'"))?
            .into_iter()
            .collect();
    }

    if let Some(from_str) = &args.from {
        f.from_ns = Some(
            parse_datetime_ns(from_str)
                .with_context(|| format!("invalid --from value '{from_str}'"))?,
        );
    }
    if let Some(to_str) = &args.to {
        f.to_ns = Some(
            parse_datetime_ns(to_str).with_context(|| format!("invalid --to value '{to_str}'"))?,
        );
    }

    if let Some(flags_str) = &args.tcp_flags {
        f.tcp_flags = Some(
            TcpFlagsFilter::parse(flags_str)
                .with_context(|| format!("invalid --tcp-flags value '{flags_str}'"))?,
        );
    }

    f.min_len = args.min_len;
    f.max_len = args.max_len;

    Ok(f)
}

/// Construct a [`TransformOptions`] from CLI arguments merged with TOML config.
///
/// CLI flags take precedence over config values. Per-protocol truncation rules
/// are TOML-only (no CLI equivalent).
fn build_transform(args: &cli::SortArgs, cfg: &TransformConfig) -> Result<TransformOptions> {
    // CLI --max-payload-bytes takes precedence over config value.
    let max_payload_bytes = args.max_payload_bytes.or(cfg.max_payload_bytes);

    let mut t = TransformOptions {
        max_payload_bytes,
        ..TransformOptions::default()
    };

    // CLI --timestamp-start takes precedence over config value.
    let ts_str = args
        .timestamp_start
        .as_deref()
        .or(cfg.timestamp_start.as_deref());
    if let Some(ts_str) = ts_str {
        t.timestamp_start_ns = Some(
            parse_datetime_ns(ts_str)
                .with_context(|| format!("invalid timestamp-start value '{ts_str}'"))?,
        );
    }

    // CLI --replace-ip takes precedence: if any CLI entries exist, ignore config.
    let ip_sources: &[String] = if !args.replace_ip.is_empty() {
        &args.replace_ip
    } else {
        &cfg.replace_ip
    };
    for s in ip_sources {
        t.ip_map
            .push(parse_ip_mapping(s).with_context(|| format!("invalid replace-ip value '{s}'"))?);
    }

    // Per-protocol truncation: TOML config only (no CLI equivalent).
    for rule in &cfg.truncate_by_proto {
        let proto = parse_proto_list(&rule.proto)
            .with_context(|| {
                format!(
                    "invalid proto '{}' in transform.truncate_by_proto",
                    rule.proto
                )
            })?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty proto in transform.truncate_by_proto"))?;
        t.proto_truncation.push(ProtocolTruncation {
            proto,
            max_payload_bytes: rule.max_payload_bytes,
        });
    }

    Ok(t)
}

fn cmd_export(args: &crate::cli::export::ExportArgs, config: &Config) -> Result<()> {
    // Validate --format if explicitly provided.
    if let Some(s) = &args.format
        && ExportFormat::parse(s).is_none()
    {
        anyhow::bail!(
            "unknown export format '{}'; expected json, parquet, or avro",
            s
        );
    }

    let filter = build_export_filter(args)?;
    let bpf_filter = args
        .filter_expr
        .as_deref()
        .map(|expr| {
            bpf::parse(expr).with_context(|| format!("invalid --filter expression '{expr}'"))
        })
        .transpose()?;

    let filter = if let Some(min_pkts) = args.min_flow_packets {
        resolve_min_flow_filter(
            &[args.input.as_path()],
            &filter,
            bpf_filter.as_ref(),
            min_pkts,
        )?
    } else {
        filter
    };

    // Resolve output targets: CLI flags take precedence over TOML config.
    let targets: Vec<OutputTarget> = if !args.outputs.is_empty() {
        args.outputs
            .iter()
            .enumerate()
            .map(|(i, path)| {
                // --format applies to the first output only (backward compat).
                let format = if i == 0 {
                    args.format
                        .as_deref()
                        .and_then(ExportFormat::parse)
                        .or_else(|| ExportFormat::from_extension(path))
                } else {
                    ExportFormat::from_extension(path)
                };
                OutputTarget {
                    path: path.clone(),
                    format,
                    compress_payload: args.compress_payload,
                }
            })
            .collect()
    } else if !config.export.outputs.is_empty() {
        // TOML [[export.outputs]] fan-out.
        config
            .export
            .outputs
            .iter()
            .map(|o| OutputTarget {
                path: o.path.clone(),
                format: o
                    .format
                    .as_deref()
                    .and_then(ExportFormat::parse)
                    .or_else(|| ExportFormat::from_extension(&o.path)),
                compress_payload: o.compress_payload,
            })
            .collect()
    } else if let Some(path) = &config.export.path {
        // TOML legacy [export] single path.
        vec![OutputTarget {
            path: path.clone(),
            format: config
                .export
                .format
                .as_deref()
                .and_then(ExportFormat::parse)
                .or_else(|| ExportFormat::from_extension(path)),
            compress_payload: config.export.compress_payload,
        }]
    } else {
        anyhow::bail!(
            "no output specified; use --output PATH or configure [[export.outputs]] in TOML"
        );
    };

    let unidirectional = args.unidirectional || config.export.unidirectional;

    let opts = MultiExportOptions {
        targets,
        filter,
        bpf_filter,
        unidirectional,
    };

    let report = export::export_multi(&args.input, &opts)
        .with_context(|| format!("failed to export {}", args.input.display()))?;

    for out in &report.outputs {
        println!(
            "Exported {} packet(s) to {}",
            out.packets_written,
            out.output_path.display()
        );
    }
    Ok(())
}

/// Build a [`Filter`] from the `export` subcommand CLI arguments.
fn build_export_filter(args: &crate::cli::export::ExportArgs) -> Result<Filter> {
    let mut f = Filter {
        unidirectional: args.unidirectional,
        negate: args.negate,
        ..Filter::default()
    };

    if let Some(proto_str) = &args.proto {
        f.protocols = parse_proto_list(proto_str)
            .with_context(|| format!("invalid --proto value '{proto_str}'"))?;
    }

    for s in &args.src_ip {
        f.src_ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --src-ip value '{s}'"))?);
    }
    for s in &args.dst_ip {
        f.dst_ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --dst-ip value '{s}'"))?);
    }
    for s in &args.ip {
        f.ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --ip value '{s}'"))?);
    }

    for s in &args.src_port {
        f.src_ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --src-port value '{s}'"))?);
    }
    for s in &args.dst_port {
        f.dst_ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --dst-port value '{s}'"))?);
    }
    for s in &args.port {
        f.ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --port value '{s}'"))?);
    }

    if let Some(ids_str) = &args.flow_id {
        f.flow_ids = parse_flow_ids(ids_str)
            .with_context(|| format!("invalid --flow-id value '{ids_str}'"))?
            .into_iter()
            .collect();
    }

    if let Some(from_str) = &args.from {
        f.from_ns = Some(
            parse_datetime_ns(from_str)
                .with_context(|| format!("invalid --from value '{from_str}'"))?,
        );
    }
    if let Some(to_str) = &args.to {
        f.to_ns = Some(
            parse_datetime_ns(to_str).with_context(|| format!("invalid --to value '{to_str}'"))?,
        );
    }

    if let Some(flags_str) = &args.tcp_flags {
        f.tcp_flags = Some(
            TcpFlagsFilter::parse(flags_str)
                .with_context(|| format!("invalid --tcp-flags value '{flags_str}'"))?,
        );
    }

    f.min_len = args.min_len;
    f.max_len = args.max_len;

    Ok(f)
}

fn cmd_replay(args: &crate::cli::replay::ReplayArgs) -> Result<()> {
    if args.interfaces.is_empty() {
        anyhow::bail!("at least one --interface is required");
    }
    if args.speed.is_some() && args.pps.is_some() {
        anyhow::bail!("--speed and --pps are mutually exclusive; use one or the other");
    }

    let speed = if let Some(n) = args.pps {
        ReplaySpeed::Pps(n)
    } else if let Some(s) = &args.speed {
        ReplaySpeed::parse(s).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --speed value '{s}': expected a positive number (e.g. 2.0) or 'max'"
            )
        })?
    } else {
        ReplaySpeed::RealTime
    };

    let filter = build_replay_filter(args)?;

    let bpf_filter = args
        .filter_expr
        .as_deref()
        .map(|expr| {
            bpf::parse(expr).with_context(|| format!("invalid --filter expression '{expr}'"))
        })
        .transpose()?;

    let filter = if let Some(min_pkts) = args.min_flow_packets {
        resolve_min_flow_filter(
            &[args.input.as_path()],
            &filter,
            bpf_filter.as_ref(),
            min_pkts,
        )?
    } else {
        filter
    };

    let opts = ReplayOptions {
        interfaces: args.interfaces.clone(),
        speed,
        filter,
        bpf_filter,
    };

    let report = replay::replay_file(&args.input, &opts)
        .with_context(|| format!("failed to replay {}", args.input.display()))?;

    let iface_list = args.interfaces.join(", ");
    println!(
        "Replayed {} packet(s) ({} bytes) on {}",
        report.packets_sent, report.bytes_sent, iface_list
    );
    Ok(())
}

/// Build a [`Filter`] from the `replay` subcommand CLI arguments.
fn build_replay_filter(args: &crate::cli::replay::ReplayArgs) -> Result<Filter> {
    let mut f = Filter {
        unidirectional: args.unidirectional,
        negate: args.negate,
        ..Filter::default()
    };

    if let Some(proto_str) = &args.proto {
        f.protocols = parse_proto_list(proto_str)
            .with_context(|| format!("invalid --proto value '{proto_str}'"))?;
    }

    for s in &args.src_ip {
        f.src_ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --src-ip value '{s}'"))?);
    }
    for s in &args.dst_ip {
        f.dst_ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --dst-ip value '{s}'"))?);
    }
    for s in &args.ip {
        f.ips
            .push(IpNet::parse(s).with_context(|| format!("invalid --ip value '{s}'"))?);
    }

    for s in &args.src_port {
        f.src_ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --src-port value '{s}'"))?);
    }
    for s in &args.dst_port {
        f.dst_ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --dst-port value '{s}'"))?);
    }
    for s in &args.port {
        f.ports
            .push(PortRange::parse(s).with_context(|| format!("invalid --port value '{s}'"))?);
    }

    if let Some(ids_str) = &args.flow_id {
        f.flow_ids = parse_flow_ids(ids_str)
            .with_context(|| format!("invalid --flow-id value '{ids_str}'"))?
            .into_iter()
            .collect();
    }

    if let Some(from_str) = &args.from {
        f.from_ns = Some(
            parse_datetime_ns(from_str)
                .with_context(|| format!("invalid --from value '{from_str}'"))?,
        );
    }
    if let Some(to_str) = &args.to {
        f.to_ns = Some(
            parse_datetime_ns(to_str).with_context(|| format!("invalid --to value '{to_str}'"))?,
        );
    }

    if let Some(flags_str) = &args.tcp_flags {
        f.tcp_flags = Some(
            TcpFlagsFilter::parse(flags_str)
                .with_context(|| format!("invalid --tcp-flags value '{flags_str}'"))?,
        );
    }

    f.min_len = args.min_len;
    f.max_len = args.max_len;

    Ok(f)
}

/// Pre-scan `inputs` to count packets per flow, then restrict `filter` to only
/// flows that have at least `min_packets` packets.
///
/// The `flow_ids` field of `filter` is intentionally ignored during counting
/// (we are computing which flow IDs qualify). After counting, any existing
/// explicit `flow_ids` are intersected with the qualifying set.
///
/// Non-IP packets are never counted and will not survive the threshold.
fn resolve_min_flow_filter(
    inputs: &[&std::path::Path],
    filter: &Filter,
    bpf_filter: Option<&bpf::BpfExpr>,
    min_packets: u64,
) -> Result<Filter> {
    use std::collections::HashMap;

    // Use a pre-filter that has flow_ids cleared so we count all flows,
    // not just the ones the user has explicitly whitelisted.
    let mut pre_filter = filter.clone();
    pre_filter.flow_ids.clear();

    // Count packets per flow across all inputs.
    let mut merged: HashMap<u64, u64> = HashMap::new();
    for path in inputs {
        let counts =
            pcap::count_flows_in_file(path, &pre_filter, bpf_filter, filter.unidirectional)
                .with_context(|| format!("flow pre-scan failed for {}", path.display()))?;
        for (id, count) in counts {
            *merged.entry(id).or_default() += count;
        }
    }

    let qualifying: FxHashSet<u64> = merged
        .into_iter()
        .filter(|(_, c)| *c >= min_packets)
        .map(|(id, _)| id)
        .collect();

    let mut effective = filter.clone();
    if effective.flow_ids.is_empty() {
        effective.flow_ids = qualifying.into_iter().collect();
    } else {
        effective.flow_ids.retain(|id| qualifying.contains(id));
    }
    Ok(effective)
}

fn format_duration(d: chrono::Duration) -> String {
    let secs = d.num_seconds();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}
