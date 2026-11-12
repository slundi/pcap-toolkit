//! `export` subcommand: context resolution and presentation.

use std::path::PathBuf;

use anyhow::{Context, Result};
use pcap_toolkit::{
    config::{Config, ExportConfig},
    export::{self, ExportFormat, MultiExportOptions, OutputDest, OutputTarget},
};

use super::{apply_min_flow, filter_args::build_filter, parse_bpf};
use crate::cli::export::ExportArgs;

/// Fully resolved inputs for one `export` invocation.
pub struct ExportContext {
    pub input: PathBuf,
    pub opts: MultiExportOptions,
}

impl ExportContext {
    /// Merge CLI arguments with the TOML config and validate them.
    ///
    /// When `--min-flow-packets` is set this performs the flow pre-scan over
    /// the input file, so it may read it.
    pub fn resolve(args: &ExportArgs, config: &Config) -> Result<Self> {
        // Validate --format if explicitly provided.
        if let Some(text) = &args.format
            && ExportFormat::parse(text).is_none()
        {
            anyhow::bail!("unknown export format '{text}'; expected json, parquet, or avro");
        }

        let filter = build_filter(args)?;
        let bpf_filter = parse_bpf(args.filter_expr.as_deref())?;
        let filter = apply_min_flow(
            &[args.input.as_path()],
            filter,
            bpf_filter.as_ref(),
            args.min_flow_packets,
        )?;

        Ok(Self {
            input: args.input.clone(),
            opts: MultiExportOptions {
                targets: resolve_targets(args, &config.export),
                filter,
                bpf_filter,
                unidirectional: args.unidirectional || config.export.unidirectional,
            },
        })
    }
}

/// Resolve the context, run the export service and print the report.
pub fn run(args: &ExportArgs, config: &Config) -> Result<()> {
    let ctx = ExportContext::resolve(args, config)?;

    let report = export::export_multi(&ctx.input, &ctx.opts)
        .with_context(|| format!("failed to export {}", ctx.input.display()))?;

    for out in &report.outputs {
        match out.dest {
            // Status must not pollute the piped JSON stream on STDOUT.
            OutputDest::Stdout => {
                eprintln!("Exported {} packet(s) to {}", out.packets_written, out.dest);
            }
            OutputDest::File(_) => {
                println!("Exported {} packet(s) to {}", out.packets_written, out.dest);
            }
        }
    }
    Ok(())
}

/// Resolve output targets. Precedence, highest first:
///
/// 1. CLI `--output` (repeatable); `--format` applies to the first one only.
/// 2. TOML `[[export.outputs]]` fan-out.
/// 3. TOML legacy `[export] path` (deprecated single output).
/// 4. JSON on STDOUT.
//
// Intentional read of the deprecated `ExportConfig::path` field for backward
// compatibility with pre-0.2 TOML configs; remove the allow once the field
// is itself removed.
#[allow(deprecated)]
pub fn resolve_targets(args: &ExportArgs, export_cfg: &ExportConfig) -> Vec<OutputTarget> {
    if !args.outputs.is_empty() {
        return args
            .outputs
            .iter()
            .enumerate()
            .map(|(idx, path)| {
                // --format applies to the first output only (backward compat).
                let format = if idx == 0 {
                    args.format
                        .as_deref()
                        .and_then(ExportFormat::parse)
                        .or_else(|| ExportFormat::from_extension(path))
                } else {
                    ExportFormat::from_extension(path)
                };
                OutputTarget {
                    dest: OutputDest::File(path.clone()),
                    format,
                    compress_payload: args.compress_payload,
                }
            })
            .collect();
    }

    if !export_cfg.outputs.is_empty() {
        return export_cfg
            .outputs
            .iter()
            .map(|out| OutputTarget {
                dest: OutputDest::File(out.path.clone()),
                format: out
                    .format
                    .as_deref()
                    .and_then(ExportFormat::parse)
                    .or_else(|| ExportFormat::from_extension(&out.path)),
                compress_payload: out.compress_payload,
            })
            .collect();
    }

    if let Some(path) = &export_cfg.path {
        return vec![OutputTarget {
            dest: OutputDest::File(path.clone()),
            format: export_cfg
                .format
                .as_deref()
                .and_then(ExportFormat::parse)
                .or_else(|| ExportFormat::from_extension(path)),
            compress_payload: export_cfg.compress_payload,
        }];
    }

    // No output given on the CLI or in TOML: stream JSON to STDOUT so the
    // result can be piped. STDOUT is JSON-only; --format may still select
    // JSON explicitly, but parquet/avro are rejected in `build_sink`.
    vec![OutputTarget {
        dest: OutputDest::Stdout,
        format: args.format.as_deref().and_then(ExportFormat::parse),
        compress_payload: args.compress_payload,
    }]
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::app::test_support::{export_args, fixture};
    use pcap_toolkit::config::ExportOutputConfig;

    fn file_dest(target: &OutputTarget) -> &std::path::Path {
        match &target.dest {
            OutputDest::File(path) => path,
            OutputDest::Stdout => panic!("expected a file destination"),
        }
    }

    // ── resolve_targets precedence ───────────────────────────────────────────

    #[test]
    fn test_targets_default_to_stdout_json() {
        let targets = resolve_targets(&export_args(), &ExportConfig::default());
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0].dest, OutputDest::Stdout));
        assert_eq!(targets[0].format, None);
    }

    #[test]
    fn test_targets_stdout_honours_cli_format_and_compress() {
        let mut args = export_args();
        args.format = Some("json".into());
        args.compress_payload = true;
        let targets = resolve_targets(&args, &ExportConfig::default());
        assert!(matches!(targets[0].dest, OutputDest::Stdout));
        assert_eq!(targets[0].format, Some(ExportFormat::Json));
        assert!(targets[0].compress_payload);
    }

    #[test]
    fn test_targets_cli_format_applies_to_first_output_only() {
        let mut args = export_args();
        args.outputs = vec![PathBuf::from("a.out"), PathBuf::from("b.parquet")];
        args.format = Some("avro".into());
        let targets = resolve_targets(&args, &ExportConfig::default());
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].format, Some(ExportFormat::Avro));
        assert_eq!(targets[1].format, Some(ExportFormat::Parquet));
        assert_eq!(file_dest(&targets[1]), std::path::Path::new("b.parquet"));
    }

    #[test]
    fn test_targets_cli_outputs_override_config() {
        let mut args = export_args();
        args.outputs = vec![PathBuf::from("cli.jsonl")];
        let cfg = ExportConfig {
            outputs: vec![ExportOutputConfig {
                path: PathBuf::from("cfg.parquet"),
                format: None,
                compress_payload: true,
            }],
            ..ExportConfig::default()
        };
        let targets = resolve_targets(&args, &cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(file_dest(&targets[0]), std::path::Path::new("cli.jsonl"));
    }

    #[test]
    fn test_targets_config_fanout() {
        let cfg = ExportConfig {
            outputs: vec![
                ExportOutputConfig {
                    path: PathBuf::from("one.data"),
                    format: Some("json".into()),
                    compress_payload: true,
                },
                ExportOutputConfig {
                    path: PathBuf::from("two.avro"),
                    format: None,
                    compress_payload: false,
                },
            ],
            path: Some(PathBuf::from("ignored.parquet")),
            ..ExportConfig::default()
        };
        let targets = resolve_targets(&export_args(), &cfg);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].format, Some(ExportFormat::Json));
        assert!(targets[0].compress_payload);
        assert_eq!(targets[1].format, Some(ExportFormat::Avro));
        assert!(!targets[1].compress_payload);
    }

    #[test]
    fn test_targets_legacy_single_path() {
        let cfg = ExportConfig {
            path: Some(PathBuf::from("legacy.data")),
            format: Some("parquet".into()),
            compress_payload: true,
            ..ExportConfig::default()
        };
        let targets = resolve_targets(&export_args(), &cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(file_dest(&targets[0]), std::path::Path::new("legacy.data"));
        assert_eq!(targets[0].format, Some(ExportFormat::Parquet));
        assert!(targets[0].compress_payload);
    }

    // ── ExportContext::resolve ───────────────────────────────────────────────

    #[test]
    fn test_resolve_rejects_unknown_format() {
        let mut args = export_args();
        args.format = Some("xml".into());
        let err = ExportContext::resolve(&args, &Config::default())
            .err()
            .unwrap();
        assert!(err.to_string().contains("unknown export format 'xml'"));
    }

    #[test]
    fn test_resolve_unidirectional_from_cli_or_config() {
        let ctx = ExportContext::resolve(&export_args(), &Config::default()).unwrap();
        assert!(!ctx.opts.unidirectional);

        let mut config = Config::default();
        config.export.unidirectional = true;
        let ctx = ExportContext::resolve(&export_args(), &config).unwrap();
        assert!(ctx.opts.unidirectional);

        let mut args = export_args();
        args.unidirectional = true;
        let ctx = ExportContext::resolve(&args, &Config::default()).unwrap();
        assert!(ctx.opts.unidirectional);
    }

    #[test]
    fn test_resolve_invalid_bpf() {
        let mut args = export_args();
        args.filter_expr = Some("host".into());
        assert!(ExportContext::resolve(&args, &Config::default()).is_err());
    }

    #[test]
    fn test_resolve_min_flow_prescan() {
        let mut args = export_args();
        args.input = fixture("mixed.pcap");
        args.min_flow_packets = Some(1);
        let ctx = ExportContext::resolve(&args, &Config::default()).unwrap();
        assert!(!ctx.opts.filter.flow_ids.is_empty());
    }

    #[test]
    fn test_run_writes_json_file() {
        let out = std::env::temp_dir().join(format!(
            "pcap_toolkit_app_export_{}.jsonl",
            std::process::id()
        ));
        let mut args = export_args();
        args.input = fixture("dns_exchange.pcap");
        args.outputs = vec![out.clone()];
        run(&args, &Config::default()).unwrap();
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.lines().count() > 0);
        let _ = std::fs::remove_file(&out);
    }
}
