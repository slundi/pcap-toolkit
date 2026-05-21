//! Binary entry point for pcap-toolkit.

mod cli;

use anyhow::{Context, Result};
use pcap_toolkit::{
    config::Config,
    filter::{
        Filter, IpNet, PortRange, TcpFlagsFilter, parse_datetime_ns, parse_flow_ids,
        parse_proto_list,
    },
    pcap,
    sort::{self, SortOptions},
    stats::{CaptureInfo, StatsCollector},
};

fn main() -> Result<()> {
    let args = cli::parser().run();

    // Load optional config file.
    let _config = match &args.config {
        Some(path) => Config::from_file(path)
            .with_context(|| format!("failed to load config from {}", path.display()))?,
        None => Config::default(),
    };

    match args.command {
        cli::Command::Info(a) => cmd_info(&a),
        cli::Command::Stats(a) => cmd_stats(&a),
        cli::Command::Sort(a) => cmd_sort(&a),
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

fn cmd_sort(args: &cli::SortArgs) -> Result<()> {
    let slice_secs = args
        .slice
        .as_deref()
        .map(sort::parse_slice)
        .transpose()
        .with_context(|| "invalid --slice value")?;

    let filter = build_filter(args)?;

    let opts = SortOptions {
        output: args.output.clone(),
        slice_secs,
        on_disk: args.on_disk,
        filter,
    };

    let report = sort::sort_file(&args.input, &opts)
        .with_context(|| format!("failed to sort {}", args.input.display()))?;

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
            .with_context(|| format!("invalid --flow-id value '{ids_str}'"))?;
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
