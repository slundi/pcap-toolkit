//! `info` and `stats` subcommands: capture summary and per-flow statistics.

use anyhow::{Context, Result};
use pcap_toolkit::{
    pcap::{self, PacketSource},
    stats::{CaptureInfo, StatsCollector},
};

use crate::cli;

/// Run `info`: print the capture summary. An input of `-` reads stdin.
pub fn run_info(args: &cli::InfoArgs) -> Result<()> {
    let info = collect_info(&PacketSource::from_arg(&args.input), false)?;
    println!("{}", render_info(&info));
    Ok(())
}

/// Run `stats`: print the capture summary and flow table, or JSON.
/// An input of `-` reads stdin.
pub fn run_stats(args: &cli::StatsArgs) -> Result<()> {
    let info = collect_info(&PacketSource::from_arg(&args.input), args.unidirectional)?;
    if args.json {
        println!("{}", stats_to_json(&info)?);
    } else {
        println!("{}", render_info(&info));
        if let Some(table) = render_flows(&info) {
            println!("{table}");
        }
    }
    Ok(())
}

/// Stream `source` (file or stdin) through a [`StatsCollector`].
pub fn collect_info(source: &PacketSource, unidirectional: bool) -> Result<CaptureInfo> {
    let mut collector = StatsCollector::new(unidirectional);
    let iter = pcap::open_source(source).with_context(|| format!("failed to open {source}"))?;

    for result in iter {
        let pkt = result.with_context(|| format!("error reading {source}"))?;
        collector.feed(pkt.timestamp_ns, pkt.captured_len, pkt.flow_key);
    }

    Ok(collector.finish())
}

/// Render the capture summary block (no trailing newline).
pub fn render_info(info: &CaptureInfo) -> String {
    let dash = || "—".to_string();
    [
        format!("Packets : {}", info.total_packets),
        format!("Bytes   : {}", info.total_bytes),
        format!(
            "Start   : {}",
            info.start.map(|ts| ts.to_rfc3339()).unwrap_or_else(dash)
        ),
        format!(
            "End     : {}",
            info.end.map(|ts| ts.to_rfc3339()).unwrap_or_else(dash)
        ),
        format!(
            "Duration: {}",
            info.duration().map(format_duration).unwrap_or_else(dash)
        ),
        format!("Src IPs : {}", info.unique_src_ips.len()),
        format!("Dst IPs : {}", info.unique_dst_ips.len()),
        format!("Flows   : {}", info.flow_count()),
    ]
    .join("\n")
}

/// Render the flow table ordered by descending byte count, preceded by a
/// blank line. Returns `None` when there are no flows.
pub fn render_flows(info: &CaptureInfo) -> Option<String> {
    if info.flows.is_empty() {
        return None;
    }

    let mut flows = info.flows.clone();
    flows.sort_by_key(|flow| std::cmp::Reverse(flow.bytes));

    let mut lines = Vec::with_capacity(flows.len() + 3);
    lines.push(String::new());
    lines.push(format!(
        "{:<20} {:<20} {:<8} {:<8} {:<5} {:>10} {:>12} {:>18}",
        "Src IP", "Dst IP", "SrcPort", "DstPort", "Proto", "Packets", "Bytes", "Flow ID"
    ));
    lines.push("-".repeat(105));
    for flow in &flows {
        lines.push(format!(
            "{:<20} {:<20} {:<8} {:<8} {:<5} {:>10} {:>12} {:>18x}",
            flow.key.src_ip.to_string(),
            flow.key.dst_ip.to_string(),
            flow.key.src_port,
            flow.key.dst_port,
            flow.key.protocol,
            flow.packets,
            flow.bytes,
            flow.flow_id,
        ));
    }
    Some(lines.join("\n"))
}

/// JSON view of a single flow. Mirrors the columns of the text table but with
/// `flow_id` as a numeric `u64` (matching the `export` JSON convention) rather
/// than hex.
#[derive(serde::Serialize)]
struct FlowJson {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    packets: u64,
    bytes: u64,
    flow_id: u64,
}

/// JSON view of an entire capture's statistics.
#[derive(serde::Serialize)]
struct StatsJson {
    packets: u64,
    bytes: u64,
    /// RFC 3339 timestamp of the first packet, or `null` for an empty capture.
    start: Option<String>,
    /// RFC 3339 timestamp of the last packet, or `null` for an empty capture.
    end: Option<String>,
    /// Capture duration in whole seconds, or `null` if fewer than two packets.
    duration_secs: Option<i64>,
    unique_src_ips: usize,
    unique_dst_ips: usize,
    flow_count: usize,
    flows: Vec<FlowJson>,
}

/// Render a [`CaptureInfo`] as pretty-printed JSON.
///
/// Flows are ordered by descending byte count to match the text table.
pub fn stats_to_json(info: &CaptureInfo) -> Result<String> {
    let mut flows = info.flows.clone();
    flows.sort_by_key(|flow| std::cmp::Reverse(flow.bytes));

    let flows_json = flows
        .into_iter()
        .map(|flow| FlowJson {
            src_ip: flow.key.src_ip.to_string(),
            dst_ip: flow.key.dst_ip.to_string(),
            src_port: flow.key.src_port,
            dst_port: flow.key.dst_port,
            protocol: flow.key.protocol,
            packets: flow.packets,
            bytes: flow.bytes,
            flow_id: flow.flow_id,
        })
        .collect();

    let view = StatsJson {
        packets: info.total_packets,
        bytes: info.total_bytes,
        start: info.start.map(|ts| ts.to_rfc3339()),
        end: info.end.map(|ts| ts.to_rfc3339()),
        duration_secs: info.duration().map(|dur| dur.num_seconds()),
        unique_src_ips: info.unique_src_ips.len(),
        unique_dst_ips: info.unique_dst_ips.len(),
        flow_count: info.flow_count(),
        flows: flows_json,
    };

    Ok(serde_json::to_string_pretty(&view)?)
}

/// Human-readable duration: `42s`, `3m 7s`, `2h 0m 5s`.
pub fn format_duration(dur: chrono::Duration) -> String {
    let secs = dur.num_seconds();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::fixture;
    use pcap_toolkit::flow::FlowKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(oct_a: u8, oct_b: u8, oct_c: u8, oct_d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(oct_a, oct_b, oct_c, oct_d))
    }

    // ── stats --json rendering ───────────────────────────────────────────────

    #[test]
    fn test_stats_json_empty_capture() {
        let info = StatsCollector::new(false).finish();
        let json = stats_to_json(&info).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val["packets"], 0);
        assert_eq!(val["bytes"], 0);
        assert!(val["start"].is_null());
        assert!(val["end"].is_null());
        assert!(val["duration_secs"].is_null());
        assert_eq!(val["unique_src_ips"], 0);
        assert_eq!(val["unique_dst_ips"], 0);
        assert_eq!(val["flow_count"], 0);
        assert!(val["flows"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_stats_json_aggregate_fields() {
        let mut col = StatsCollector::new(false);
        let key = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1000, 443, 6);
        col.feed(1_000_000_000, 100, Some(key.clone()));
        col.feed(3_000_000_000, 200, Some(key));
        let info = col.finish();

        let json = stats_to_json(&info).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val["packets"], 2);
        assert_eq!(val["bytes"], 300);
        assert_eq!(val["unique_src_ips"], 1);
        assert_eq!(val["unique_dst_ips"], 1);
        assert_eq!(val["flow_count"], 1);
        // Two packets, 2s apart.
        assert_eq!(val["duration_secs"], 2);
        assert!(val["start"].as_str().unwrap().contains("1970"));
        assert!(val["end"].is_string());
    }

    #[test]
    fn test_stats_json_flow_details() {
        // Unidirectional so the raw 5-tuple is preserved (no canonical reorder),
        // keeping the src/dst field assertions direction-stable.
        let mut col = StatsCollector::new(true);
        let key = FlowKey::new(v4(192, 168, 1, 1), v4(8, 8, 8, 8), 5000, 53, 17);
        let expected_flow_id = key.flow_id(true);
        col.feed(1_000_000_000, 60, Some(key));
        let info = col.finish();

        let json = stats_to_json(&info).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        let flow = &val["flows"][0];
        assert_eq!(flow["src_ip"], "192.168.1.1");
        assert_eq!(flow["dst_ip"], "8.8.8.8");
        assert_eq!(flow["src_port"], 5000);
        assert_eq!(flow["dst_port"], 53);
        assert_eq!(flow["protocol"], 17);
        assert_eq!(flow["packets"], 1);
        assert_eq!(flow["bytes"], 60);
        // flow_id is emitted as a numeric u64 (not hex), matching export JSON.
        assert!(flow["flow_id"].is_u64());
        assert_eq!(flow["flow_id"].as_u64().unwrap(), expected_flow_id);
    }

    #[test]
    fn test_stats_json_flows_sorted_by_bytes_desc() {
        let mut col = StatsCollector::new(false);
        // Small flow first, large flow second — output must list large first.
        let small = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1111, 80, 6);
        let large = FlowKey::new(v4(10, 0, 0, 3), v4(10, 0, 0, 4), 2222, 443, 6);
        col.feed(1_000_000_000, 50, Some(small));
        col.feed(2_000_000_000, 5000, Some(large));
        let info = col.finish();

        let json = stats_to_json(&info).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        let flows = val["flows"].as_array().unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0]["bytes"], 5000);
        assert_eq!(flows[1]["bytes"], 50);
    }

    // ── text rendering ───────────────────────────────────────────────────────

    #[test]
    fn test_render_info_empty_uses_dashes() {
        let text = render_info(&StatsCollector::new(false).finish());
        assert!(text.starts_with("Packets : 0\n"));
        assert!(text.contains("Start   : —"));
        assert!(text.contains("Duration: —"));
        assert!(text.ends_with("Flows   : 0"));
        assert_eq!(text.lines().count(), 8);
    }

    #[test]
    fn test_render_flows_none_when_empty() {
        assert!(render_flows(&StatsCollector::new(false).finish()).is_none());
    }

    #[test]
    fn test_render_flows_sorted_desc_with_hex_id() {
        let mut col = StatsCollector::new(true);
        let small = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1111, 80, 6);
        let large = FlowKey::new(v4(10, 0, 0, 3), v4(10, 0, 0, 4), 2222, 443, 6);
        let large_id = large.flow_id(true);
        col.feed(1_000_000_000, 50, Some(small));
        col.feed(2_000_000_000, 5000, Some(large));
        let table = render_flows(&col.finish()).unwrap();

        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines[0], "");
        assert!(lines[1].starts_with("Src IP"));
        assert_eq!(lines[2], "-".repeat(105));
        assert!(lines[3].starts_with("10.0.0.3"));
        assert!(lines[3].ends_with(&format!("{large_id:x}")));
        assert!(lines[4].starts_with("10.0.0.1"));
    }

    #[test]
    fn test_format_duration_buckets() {
        assert_eq!(format_duration(chrono::Duration::seconds(42)), "42s");
        assert_eq!(format_duration(chrono::Duration::seconds(187)), "3m 7s");
        assert_eq!(format_duration(chrono::Duration::seconds(7205)), "2h 0m 5s");
    }

    // ── collect_info over fixtures ───────────────────────────────────────────

    #[test]
    fn test_collect_info_from_fixture() {
        let source = PacketSource::File(fixture("dns_exchange.pcap"));
        let info = collect_info(&source, false).unwrap();
        assert!(info.total_packets > 0);
        assert!(info.flow_count() > 0);
    }

    #[test]
    fn test_collect_info_missing_file() {
        let source = PacketSource::File("/nonexistent/nope.pcap".into());
        let err = collect_info(&source, false).unwrap_err();
        assert!(format!("{err:#}").contains("failed to open /nonexistent/nope.pcap"));
    }

    #[test]
    fn test_run_info_and_stats_succeed_on_fixture() {
        let input = fixture("http_session.pcap");
        run_info(&cli::InfoArgs {
            input: input.clone(),
        })
        .unwrap();
        for json in [false, true] {
            run_stats(&cli::StatsArgs {
                input: input.clone(),
                unidirectional: false,
                json,
            })
            .unwrap();
        }
    }
}
