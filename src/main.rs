//! Binary entry point for pcap-toolkit.
//!
//! Parses the command line, loads the optional TOML config, and dispatches to
//! the per-subcommand context layer in [`app`].

mod app;
mod cli;

use anyhow::{Context, Result};
use pcap_toolkit::config::Config;

fn main() -> Result<()> {
    let args = cli::parser().run();

    // Load optional config file.
    let config = match &args.config {
        Some(path) => Config::from_file(path)
            .with_context(|| format!("failed to load config from {}", path.display()))?,
        None => Config::default(),
    };

    match args.command {
        cli::Command::Info(sub) => app::stats::run_info(&sub),
        cli::Command::Stats(sub) => app::stats::run_stats(&sub),
        cli::Command::Sort(sub) => app::sort::run(&sub, &config),
        cli::Command::Export(sub) => app::export::run(&sub, &config),
        cli::Command::Replay(sub) => app::replay::run(&sub),
    }
}
