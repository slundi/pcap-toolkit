//! `replay` subcommand: context resolution and presentation.

use anyhow::{Context, Result};
use pcap_toolkit::{
    pcap::PacketSource,
    replay::{self, ReplayOptions, ReplaySpeed},
};

use super::{apply_min_flow_to_source, filter_args::build_filter, parse_bpf};
use crate::cli::replay::ReplayArgs;

/// Fully resolved inputs for one `replay` invocation.
pub struct ReplayContext {
    pub input: PacketSource,
    pub opts: ReplayOptions,
}

impl ReplayContext {
    /// Validate CLI arguments and build the replay options.
    ///
    /// An input of `-` reads from stdin. When `--min-flow-packets` is set this
    /// performs the flow pre-scan over the input file (so it may read it), and
    /// is rejected for stdin.
    pub fn resolve(args: &ReplayArgs) -> Result<Self> {
        if args.interfaces.is_empty() {
            anyhow::bail!("at least one --interface is required");
        }

        let input = PacketSource::from_arg(&args.input);
        let speed = resolve_speed(args.speed.as_deref(), args.pps)?;
        let filter = build_filter(args)?;
        let bpf_filter = parse_bpf(args.filter_expr.as_deref())?;
        let filter =
            apply_min_flow_to_source(&input, filter, bpf_filter.as_ref(), args.min_flow_packets)?;

        Ok(Self {
            input,
            opts: ReplayOptions {
                interfaces: args.interfaces.clone(),
                speed,
                filter,
                bpf_filter,
            },
        })
    }
}

/// Resolve the context, run the replay service and print the report.
pub fn run(args: &ReplayArgs) -> Result<()> {
    let ctx = ReplayContext::resolve(args)?;

    let report = replay::replay_file(&ctx.input, &ctx.opts)
        .with_context(|| format!("failed to replay {}", ctx.input))?;

    println!(
        "Replayed {} packet(s) ({} bytes) on {}",
        report.packets_sent,
        report.bytes_sent,
        ctx.opts.interfaces.join(", ")
    );
    Ok(())
}

/// Pick the pacing mode from `--speed` / `--pps` (mutually exclusive).
/// Defaults to real-time when neither is given.
pub fn resolve_speed(speed: Option<&str>, pps: Option<u64>) -> Result<ReplaySpeed> {
    match (speed, pps) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--speed and --pps are mutually exclusive; use one or the other")
        }
        (None, Some(rate)) => Ok(ReplaySpeed::Pps(rate)),
        (Some(text), None) => ReplaySpeed::parse(text).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --speed value '{text}': expected a positive number (e.g. 2.0) or 'max'"
            )
        }),
        (None, None) => Ok(ReplaySpeed::RealTime),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::{fixture, replay_args};

    #[test]
    fn test_speed_defaults_to_real_time() {
        assert!(matches!(
            resolve_speed(None, None).unwrap(),
            ReplaySpeed::RealTime
        ));
    }

    #[test]
    fn test_speed_pps() {
        assert!(matches!(
            resolve_speed(None, Some(500)).unwrap(),
            ReplaySpeed::Pps(500)
        ));
    }

    #[test]
    fn test_speed_parsed() {
        assert!(matches!(
            resolve_speed(Some("max"), None).unwrap(),
            ReplaySpeed::Max
        ));
        assert!(matches!(
            resolve_speed(Some("2.0"), None).unwrap(),
            ReplaySpeed::Multiplier(_)
        ));
    }

    #[test]
    fn test_speed_and_pps_are_exclusive() {
        let err = resolve_speed(Some("2.0"), Some(10)).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_speed_invalid() {
        let err = resolve_speed(Some("fast"), None).unwrap_err();
        assert!(err.to_string().contains("invalid --speed value 'fast'"));
    }

    #[test]
    fn test_resolve_requires_interface() {
        let err = ReplayContext::resolve(&replay_args()).err().unwrap();
        assert!(err.to_string().contains("--interface"));
    }

    #[test]
    fn test_resolve_builds_options() {
        let mut args = replay_args();
        args.interfaces = vec!["lo".into(), "eth0".into()];
        args.pps = Some(100);
        args.proto = Some("udp".into());
        args.filter_expr = Some("port 53".into());
        let ctx = ReplayContext::resolve(&args).unwrap();
        assert_eq!(ctx.opts.interfaces, ["lo", "eth0"]);
        assert!(matches!(ctx.opts.speed, ReplaySpeed::Pps(100)));
        assert!(ctx.opts.filter.protocols.contains(&17));
        assert!(ctx.opts.bpf_filter.is_some());
    }

    #[test]
    fn test_resolve_min_flow_prescan() {
        let mut args = replay_args();
        args.interfaces = vec!["lo".into()];
        args.input = fixture("mixed.pcap");
        args.min_flow_packets = Some(u64::MAX);
        let ctx = ReplayContext::resolve(&args).unwrap();
        assert!(ctx.opts.filter.flow_ids.is_empty());
    }

    #[test]
    fn test_resolve_dash_selects_stdin() {
        let mut args = replay_args();
        args.interfaces = vec!["lo".into()];
        args.input = std::path::PathBuf::from("-");
        let ctx = ReplayContext::resolve(&args).unwrap();
        assert_eq!(ctx.input, PacketSource::Stdin);
    }

    #[test]
    fn test_resolve_stdin_rejects_min_flow() {
        let mut args = replay_args();
        args.interfaces = vec!["lo".into()];
        args.input = std::path::PathBuf::from("-");
        args.min_flow_packets = Some(2);
        let err = ReplayContext::resolve(&args).err().unwrap();
        assert!(err.to_string().contains("stdin"));
    }
}
