//! Application (context) layer of the binary.
//!
//! Each subcommand has a module that:
//! 1. **resolves** a context — merges CLI arguments with the TOML [`Config`],
//!    validates them and builds the library's `*Options` struct;
//! 2. **runs** the matching library service (`sort_files`, `export_multi`,
//!    `replay_file`, `StatsCollector`) with that context;
//! 3. **presents** the returned report on STDOUT/STDERR.
//!
//! Keeping step 1 separate from I/O makes the CLI/TOML precedence rules
//! unit-testable without executing a command.
//!
//! [`Config`]: pcap_toolkit::config::Config

pub mod export;
pub mod filter_args;
pub mod replay;
pub mod sort;
pub mod stats;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use pcap_toolkit::{
    bpf::{self, BpfExpr},
    filter::Filter,
    pcap,
};
use rustc_hash::FxHashSet;

/// Parse an optional `--filter` BPF expression.
pub fn parse_bpf(expr: Option<&str>) -> Result<Option<BpfExpr>> {
    expr.map(|text| {
        bpf::parse(text).with_context(|| format!("invalid --filter expression '{text}'"))
    })
    .transpose()
}

/// Apply the optional minimum-packets-per-flow threshold to `filter`.
///
/// Returns `filter` unchanged when `min_packets` is `None`; otherwise performs
/// the pre-scan described in [`resolve_min_flow_filter`].
pub fn apply_min_flow(
    inputs: &[&Path],
    filter: Filter,
    bpf_filter: Option<&BpfExpr>,
    min_packets: Option<u64>,
) -> Result<Filter> {
    match min_packets {
        Some(threshold) => resolve_min_flow_filter(inputs, &filter, bpf_filter, threshold),
        None => Ok(filter),
    }
}

/// Pre-scan `inputs` to count packets per flow, then restrict `filter` to only
/// flows that have at least `min_packets` packets.
///
/// The `flow_ids` field of `filter` is intentionally ignored during counting
/// (we are computing which flow IDs qualify). After counting, any existing
/// explicit `flow_ids` are intersected with the qualifying set.
///
/// Non-IP packets are never counted and will not survive the threshold.
pub fn resolve_min_flow_filter(
    inputs: &[&Path],
    filter: &Filter,
    bpf_filter: Option<&BpfExpr>,
    min_packets: u64,
) -> Result<Filter> {
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
        for (flow_id, count) in counts {
            *merged.entry(flow_id).or_default() += count;
        }
    }

    let qualifying: FxHashSet<u64> = merged
        .into_iter()
        .filter(|(_, count)| *count >= min_packets)
        .map(|(flow_id, _)| flow_id)
        .collect();

    let mut effective = filter.clone();
    if effective.flow_ids.is_empty() {
        effective.flow_ids = qualifying.into_iter().collect();
    } else {
        effective
            .flow_ids
            .retain(|flow_id| qualifying.contains(flow_id));
    }
    Ok(effective)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Minimal argument constructors shared by the context-layer tests.

    use crate::cli;
    use std::path::PathBuf;

    /// Path to a checked-in fixture under `tests/fixtures/`.
    pub fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    pub fn sort_args() -> cli::SortArgs {
        cli::SortArgs {
            inputs: vec![],
            output: PathBuf::from("/dev/null"),
            slice: None,
            on_disk: false,
            proto: None,
            src_ip: vec![],
            dst_ip: vec![],
            ip: vec![],
            src_port: vec![],
            dst_port: vec![],
            port: vec![],
            flow_id: None,
            from: None,
            to: None,
            tcp_flags: None,
            min_len: None,
            max_len: None,
            unidirectional: false,
            negate: false,
            filter_expr: None,
            min_flow_packets: None,
            max_payload_bytes: None,
            mtu_trunc: None,
            timestamp_start: None,
            replace_ip: vec![],
        }
    }

    pub fn export_args() -> cli::export::ExportArgs {
        cli::export::ExportArgs {
            input: PathBuf::from("/dev/null"),
            outputs: vec![],
            format: None,
            compress_payload: false,
            proto: None,
            src_ip: vec![],
            dst_ip: vec![],
            ip: vec![],
            src_port: vec![],
            dst_port: vec![],
            port: vec![],
            flow_id: None,
            from: None,
            to: None,
            tcp_flags: None,
            min_len: None,
            max_len: None,
            unidirectional: false,
            negate: false,
            filter_expr: None,
            min_flow_packets: None,
        }
    }

    pub fn replay_args() -> cli::replay::ReplayArgs {
        cli::replay::ReplayArgs {
            input: PathBuf::from("/dev/null"),
            interfaces: vec![],
            speed: None,
            pps: None,
            proto: None,
            src_ip: vec![],
            dst_ip: vec![],
            ip: vec![],
            src_port: vec![],
            dst_port: vec![],
            port: vec![],
            flow_id: None,
            from: None,
            to: None,
            tcp_flags: None,
            min_len: None,
            max_len: None,
            unidirectional: false,
            negate: false,
            filter_expr: None,
            min_flow_packets: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::fixture;
    use super::*;

    #[test]
    fn test_parse_bpf_none_is_none() {
        assert!(parse_bpf(None).unwrap().is_none());
    }

    #[test]
    fn test_parse_bpf_valid_expression() {
        assert!(parse_bpf(Some("tcp and port 80")).unwrap().is_some());
    }

    #[test]
    fn test_parse_bpf_invalid_expression_mentions_input() {
        let err = parse_bpf(Some("tcp and and")).unwrap_err();
        assert!(format!("{err:#}").contains("tcp and and"));
    }

    #[test]
    fn test_apply_min_flow_none_is_identity() {
        let filter = Filter {
            min_len: Some(42),
            ..Filter::default()
        };
        let out = apply_min_flow(&[], filter, None, None).unwrap();
        assert_eq!(out.min_len, Some(42));
        assert!(out.flow_ids.is_empty());
    }

    #[test]
    fn test_min_flow_threshold_selects_flows_from_fixture() {
        let path = fixture("mixed.pcap");
        let low = resolve_min_flow_filter(&[path.as_path()], &Filter::default(), None, 1).unwrap();
        assert!(
            !low.flow_ids.is_empty(),
            "threshold 1 must keep every IP flow"
        );

        let high =
            resolve_min_flow_filter(&[path.as_path()], &Filter::default(), None, u64::MAX).unwrap();
        // No flow reaches u64::MAX packets → every explicit/implicit ID dropped.
        assert!(high.flow_ids.is_empty());
    }

    #[test]
    fn test_min_flow_intersects_explicit_flow_ids() {
        let path = fixture("mixed.pcap");
        let all = resolve_min_flow_filter(&[path.as_path()], &Filter::default(), None, 1).unwrap();
        let kept_id = *all.flow_ids.iter().next().unwrap();

        // Explicit list = one qualifying ID + one bogus ID.
        let explicit = Filter {
            flow_ids: [kept_id, 0xDEAD_BEEF_DEAD_BEEF].into_iter().collect(),
            ..Filter::default()
        };
        let out = resolve_min_flow_filter(&[path.as_path()], &explicit, None, 1).unwrap();
        assert_eq!(out.flow_ids.len(), 1);
        assert!(out.flow_ids.contains(&kept_id));
    }

    #[test]
    fn test_min_flow_missing_file_reports_path() {
        let missing = Path::new("/nonexistent/definitely-missing.pcap");
        let err = resolve_min_flow_filter(&[missing], &Filter::default(), None, 1).unwrap_err();
        assert!(format!("{err:#}").contains("definitely-missing.pcap"));
    }
}
