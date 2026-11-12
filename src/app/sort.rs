//! `sort` subcommand: context resolution and presentation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use pcap_toolkit::{
    config::{Config, TransformConfig},
    filter::{parse_datetime_ns, parse_proto_list},
    pcap::PacketSource,
    sort::{self, SortOptions},
    transform::{ProtocolTruncation, TransformOptions, parse_ip_mapping},
};

use super::{apply_min_flow, filter_args::build_filter, parse_bpf};
use crate::cli;

/// Fully resolved inputs for one `sort` invocation.
pub struct SortContext {
    pub inputs: Vec<PathBuf>,
    pub opts: SortOptions,
}

impl SortContext {
    /// Merge CLI arguments with the TOML config and validate them.
    ///
    /// When a minimum-packets-per-flow threshold is set (CLI or TOML), this
    /// performs the flow pre-scan over all inputs to compute the effective
    /// filter, so it may read the input files.
    pub fn resolve(args: &cli::SortArgs, config: &Config) -> Result<Self> {
        if args.inputs.is_empty() {
            anyhow::bail!("sort requires at least one input file");
        }
        // The second pass seeks back to each packet, so every input must be a
        // real file. Catch `-` here instead of failing on a file named "-".
        if args
            .inputs
            .iter()
            .any(|path| PacketSource::from_arg(path).is_stdin())
        {
            anyhow::bail!(
                "sort needs seekable input files and cannot read stdin ('-'); \
                 save the capture to a file first"
            );
        }

        let slice_secs = args
            .slice
            .as_deref()
            .map(sort::parse_slice)
            .transpose()
            .with_context(|| "invalid --slice value")?;

        let filter = build_filter(args)?;
        let bpf_filter = parse_bpf(args.filter_expr.as_deref())?;
        let transform = build_transform(args, &config.transform)?;

        // CLI --min-flow-packets takes precedence over TOML config value.
        let min_flow_packets = args.min_flow_packets.or(config.filter.min_flow_packets);
        let input_paths: Vec<&Path> = args.inputs.iter().map(PathBuf::as_path).collect();
        let filter = apply_min_flow(&input_paths, filter, bpf_filter.as_ref(), min_flow_packets)?;

        Ok(Self {
            inputs: args.inputs.clone(),
            opts: SortOptions {
                output: args.output.clone(),
                slice_secs,
                on_disk: args.on_disk,
                filter,
                bpf_filter,
                transform,
            },
        })
    }
}

/// Resolve the context, run the sort service and print the report.
pub fn run(args: &cli::SortArgs, config: &Config) -> Result<()> {
    let ctx = SortContext::resolve(args, config)?;
    let input_paths: Vec<&Path> = ctx.inputs.iter().map(PathBuf::as_path).collect();

    let report = sort::sort_files(&input_paths, &ctx.opts)
        .with_context(|| "failed to sort input file(s)")?;

    println!(
        "Sorted {} packet(s) into {} file(s):",
        report.packets_written,
        report.files_written.len()
    );
    for path in &report.files_written {
        println!("  {}", path.display());
    }
    Ok(())
}

/// Construct a [`TransformOptions`] from CLI arguments merged with TOML config.
///
/// CLI flags take precedence over config values. Per-protocol truncation rules
/// are TOML-only (no CLI equivalent).
pub fn build_transform(args: &cli::SortArgs, cfg: &TransformConfig) -> Result<TransformOptions> {
    let mut transform = TransformOptions {
        max_payload_bytes: args.max_payload_bytes.or(cfg.max_payload_bytes),
        mtu_trunc: args.mtu_trunc.or(cfg.mtu_trunc),
        ..TransformOptions::default()
    };

    // CLI --timestamp-start takes precedence over config value.
    let ts_str = args
        .timestamp_start
        .as_deref()
        .or(cfg.timestamp_start.as_deref());
    if let Some(ts_str) = ts_str {
        transform.timestamp_start_ns = Some(
            parse_datetime_ns(ts_str)
                .with_context(|| format!("invalid timestamp-start value '{ts_str}'"))?,
        );
    }

    // CLI --replace-ip takes precedence: if any CLI entries exist, ignore config.
    let ip_sources: &[String] = if args.replace_ip.is_empty() {
        &cfg.replace_ip
    } else {
        &args.replace_ip
    };
    for text in ip_sources {
        transform.ip_map.push(
            parse_ip_mapping(text).with_context(|| format!("invalid replace-ip value '{text}'"))?,
        );
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
        transform.proto_truncation.push(ProtocolTruncation {
            proto,
            max_payload_bytes: rule.max_payload_bytes,
        });
    }

    Ok(transform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::{fixture, sort_args};
    use pcap_toolkit::config::ProtocolTruncationConfig;

    fn args_with_input() -> cli::SortArgs {
        let mut args = sort_args();
        args.inputs = vec![fixture("mixed.pcap")];
        args
    }

    // ── SortContext::resolve ─────────────────────────────────────────────────

    #[test]
    fn test_resolve_requires_input() {
        let err = SortContext::resolve(&sort_args(), &Config::default())
            .err()
            .unwrap();
        assert!(err.to_string().contains("at least one input"));
    }

    #[test]
    fn test_resolve_rejects_stdin_input() {
        let mut args = args_with_input();
        args.inputs.push(PathBuf::from("-"));
        let err = SortContext::resolve(&args, &Config::default())
            .err()
            .unwrap();
        assert!(err.to_string().contains("seekable"));
    }

    #[test]
    fn test_resolve_defaults() {
        let ctx = SortContext::resolve(&args_with_input(), &Config::default()).unwrap();
        assert_eq!(ctx.inputs, vec![fixture("mixed.pcap")]);
        assert_eq!(ctx.opts.output, PathBuf::from("/dev/null"));
        assert!(ctx.opts.slice_secs.is_none());
        assert!(!ctx.opts.on_disk);
        assert!(ctx.opts.filter.is_empty());
        assert!(ctx.opts.bpf_filter.is_none());
        assert!(ctx.opts.transform.is_empty());
    }

    #[test]
    fn test_resolve_parses_slice_and_bpf() {
        let mut args = args_with_input();
        args.slice = Some("1h".into());
        args.filter_expr = Some("udp".into());
        args.on_disk = true;
        let ctx = SortContext::resolve(&args, &Config::default()).unwrap();
        assert_eq!(ctx.opts.slice_secs, Some(3600));
        assert!(ctx.opts.bpf_filter.is_some());
        assert!(ctx.opts.on_disk);
    }

    #[test]
    fn test_resolve_invalid_slice() {
        let mut args = args_with_input();
        args.slice = Some("forever".into());
        let err = SortContext::resolve(&args, &Config::default())
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("--slice"));
    }

    #[test]
    fn test_resolve_invalid_bpf() {
        let mut args = args_with_input();
        args.filter_expr = Some("port".into());
        assert!(SortContext::resolve(&args, &Config::default()).is_err());
    }

    #[test]
    fn test_resolve_min_flow_from_config_when_cli_absent() {
        let mut config = Config::default();
        config.filter.min_flow_packets = Some(u64::MAX);
        let ctx = SortContext::resolve(&args_with_input(), &config).unwrap();
        // Unreachable threshold → empty qualifying set.
        assert!(ctx.opts.filter.flow_ids.is_empty());

        config.filter.min_flow_packets = Some(1);
        let ctx = SortContext::resolve(&args_with_input(), &config).unwrap();
        assert!(!ctx.opts.filter.flow_ids.is_empty());
    }

    #[test]
    fn test_resolve_min_flow_cli_overrides_config() {
        let mut config = Config::default();
        config.filter.min_flow_packets = Some(u64::MAX);
        let mut args = args_with_input();
        args.min_flow_packets = Some(1);
        let ctx = SortContext::resolve(&args, &config).unwrap();
        assert!(!ctx.opts.filter.flow_ids.is_empty());
    }

    #[test]
    fn test_run_writes_sorted_output() {
        let out =
            std::env::temp_dir().join(format!("pcap_toolkit_app_sort_{}.pcap", std::process::id()));
        let mut args = args_with_input();
        args.output = out.clone();
        run(&args, &Config::default()).unwrap();
        assert!(std::fs::metadata(&out).unwrap().len() > 24);
        let _ = std::fs::remove_file(&out);
    }

    // ── build_transform ──────────────────────────────────────────────────────

    #[test]
    fn test_transform_empty_by_default() {
        let transform = build_transform(&sort_args(), &TransformConfig::default()).unwrap();
        assert!(transform.is_empty());
    }

    #[test]
    fn test_transform_config_used_when_cli_absent() {
        let cfg = TransformConfig {
            max_payload_bytes: Some(64),
            mtu_trunc: Some(1400),
            timestamp_start: Some("1000".into()),
            replace_ip: vec!["10.0.0.1=192.168.0.1".into()],
            truncate_by_proto: vec![],
        };
        let transform = build_transform(&sort_args(), &cfg).unwrap();
        assert_eq!(transform.max_payload_bytes, Some(64));
        assert_eq!(transform.mtu_trunc, Some(1400));
        assert_eq!(transform.timestamp_start_ns, Some(1_000 * 1_000_000_000));
        assert_eq!(transform.ip_map.len(), 1);
    }

    #[test]
    fn test_transform_cli_overrides_config() {
        let cfg = TransformConfig {
            max_payload_bytes: Some(64),
            mtu_trunc: Some(1400),
            timestamp_start: Some("1000".into()),
            replace_ip: vec!["10.0.0.1=192.168.0.1".into(), "10.0.0.2=192.168.0.2".into()],
            truncate_by_proto: vec![],
        };
        let mut args = sort_args();
        args.max_payload_bytes = Some(128);
        args.mtu_trunc = Some(9000);
        args.timestamp_start = Some("2000".into());
        args.replace_ip = vec!["10.0.0.9=172.16.0.9".into()];

        let transform = build_transform(&args, &cfg).unwrap();
        assert_eq!(transform.max_payload_bytes, Some(128));
        assert_eq!(transform.mtu_trunc, Some(9000));
        assert_eq!(transform.timestamp_start_ns, Some(2_000 * 1_000_000_000));
        // CLI list replaces (not extends) the config list.
        assert_eq!(transform.ip_map.len(), 1);
    }

    #[test]
    fn test_transform_per_proto_rules_from_config() {
        let cfg = TransformConfig {
            truncate_by_proto: vec![
                ProtocolTruncationConfig {
                    proto: "tcp".into(),
                    max_payload_bytes: 128,
                },
                ProtocolTruncationConfig {
                    proto: "udp".into(),
                    max_payload_bytes: 32,
                },
            ],
            ..TransformConfig::default()
        };
        let transform = build_transform(&sort_args(), &cfg).unwrap();
        assert_eq!(transform.proto_truncation.len(), 2);
        assert_eq!(transform.proto_truncation[0].proto, 6);
        assert_eq!(transform.proto_truncation[0].max_payload_bytes, 128);
        assert_eq!(transform.proto_truncation[1].proto, 17);
    }

    #[test]
    fn test_transform_invalid_values_rejected() {
        let mut args = sort_args();
        args.timestamp_start = Some("not-a-date".into());
        let err = build_transform(&args, &TransformConfig::default()).unwrap_err();
        assert!(format!("{err:#}").contains("timestamp-start"));

        let mut args = sort_args();
        args.replace_ip = vec!["garbage".into()];
        let err = build_transform(&args, &TransformConfig::default()).unwrap_err();
        assert!(format!("{err:#}").contains("replace-ip"));

        let cfg = TransformConfig {
            truncate_by_proto: vec![ProtocolTruncationConfig {
                proto: "bogus".into(),
                max_payload_bytes: 1,
            }],
            ..TransformConfig::default()
        };
        let err = build_transform(&sort_args(), &cfg).unwrap_err();
        assert!(format!("{err:#}").contains("truncate_by_proto"));
    }
}
