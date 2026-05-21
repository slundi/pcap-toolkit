//! TOML configuration types for pcap-toolkit.
//!
//! CLI flags take precedence over config file values.
//! Parsing uses [`toml_span`] — no serde dependency for config.

use std::path::PathBuf;

use toml_span::{DeserError, Deserialize, Value, de_helpers::TableHelper};

use crate::error::ConfigError;

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Default)]
pub struct Config {
    /// Input PCAP files (supports glob patterns).
    pub input: Vec<InputConfig>,

    /// Sorting options.
    pub sort: SortConfig,

    /// Packet filter options.
    pub filter: FilterConfig,

    /// Output targets.
    pub output: Vec<OutputConfig>,

    /// Live replay options.
    pub replay: ReplayConfig,
}

/// Input source configuration.
#[derive(Debug)]
pub struct InputConfig {
    /// Path or glob pattern to PCAP file(s).
    pub path: String,
}

/// Sorting configuration.
#[derive(Debug, Default)]
pub struct SortConfig {
    /// Enable two-pass chronological sorting.
    pub enabled: bool,

    /// Time-slice interval for splitting output (e.g. `"1h"`, `"1d"`).
    pub slice: Option<String>,
}

/// Filter configuration.
#[derive(Debug, Default)]
pub struct FilterConfig {
    /// IP protocols to keep (e.g. `["tcp", "udp"]`).
    pub proto: Vec<String>,

    /// Source IP addresses / CIDRs to keep (OR-ed).
    pub src_ip: Vec<String>,

    /// Destination IP addresses / CIDRs to keep (OR-ed).
    pub dst_ip: Vec<String>,

    /// Either-endpoint IP addresses / CIDRs (OR-ed).
    pub ip: Vec<String>,

    /// Source port or range strings to keep (OR-ed).
    pub src_port: Vec<String>,

    /// Destination port or range strings to keep (OR-ed).
    pub dst_port: Vec<String>,

    /// Either-endpoint port or range strings (OR-ed).
    pub port: Vec<String>,

    /// Hex flow IDs to retain (comma-separated or multiple entries).
    pub flow_id: Vec<String>,

    /// Retain only packets at or after this datetime (RFC 3339 or ms epoch).
    pub from: Option<String>,

    /// Retain only packets at or before this datetime (RFC 3339 or ms epoch).
    pub to: Option<String>,

    /// TCP flags filter string (e.g. `"SYN+ACK"`, `"RST:exact"`).
    pub tcp_flags: Option<String>,

    /// Minimum captured packet length in bytes.
    pub min_len: Option<u32>,

    /// Maximum captured packet length in bytes.
    pub max_len: Option<u32>,

    /// Use unidirectional flow IDs (default: bidirectional).
    pub unidirectional: bool,
}

/// Output target configuration.
#[derive(Debug)]
pub struct OutputConfig {
    /// Output format: `"pcap"`, `"json"`, `"parquet"`, or `"avro"`.
    pub format: String,

    /// Output file path.
    pub path: PathBuf,

    /// Compress payload field (JSON / Parquet).
    pub compress_payload: bool,
}

/// Live replay configuration.
#[derive(Debug)]
pub struct ReplayConfig {
    /// Network interface name for replay.
    pub interface: Option<String>,

    /// Replay speed multiplier (1.0 = real-time).
    pub speed: f64,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            interface: None,
            speed: 1.0,
        }
    }
}

// ── toml_span::Deserialize implementations ──────────────────────────────────

impl<'de> Deserialize<'de> for Config {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let input = th.optional::<Vec<InputConfig>>("input").unwrap_or_default();
        let sort = th.optional::<SortConfig>("sort").unwrap_or_default();
        let filter = th.optional::<FilterConfig>("filter").unwrap_or_default();
        let output = th
            .optional::<Vec<OutputConfig>>("output")
            .unwrap_or_default();
        let replay = th.optional::<ReplayConfig>("replay").unwrap_or_default();
        th.finalize(None)?;
        Ok(Config {
            input,
            sort,
            filter,
            output,
            replay,
        })
    }
}

impl<'de> Deserialize<'de> for InputConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let path = th.required::<String>("path")?;
        th.finalize(None)?;
        Ok(InputConfig { path })
    }
}

impl<'de> Deserialize<'de> for SortConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let enabled = th.optional::<bool>("enabled").unwrap_or(false);
        let slice = th.optional::<String>("slice");
        th.finalize(None)?;
        Ok(SortConfig { enabled, slice })
    }
}

impl<'de> Deserialize<'de> for FilterConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let proto = th.optional::<Vec<String>>("proto").unwrap_or_default();
        let src_ip = th.optional::<Vec<String>>("src_ip").unwrap_or_default();
        let dst_ip = th.optional::<Vec<String>>("dst_ip").unwrap_or_default();
        let ip = th.optional::<Vec<String>>("ip").unwrap_or_default();
        let src_port = th.optional::<Vec<String>>("src_port").unwrap_or_default();
        let dst_port = th.optional::<Vec<String>>("dst_port").unwrap_or_default();
        let port = th.optional::<Vec<String>>("port").unwrap_or_default();
        let flow_id = th.optional::<Vec<String>>("flow_id").unwrap_or_default();
        let from = th.optional::<String>("from");
        let to = th.optional::<String>("to");
        let tcp_flags = th.optional::<String>("tcp_flags");
        let min_len = th.optional::<u32>("min_len");
        let max_len = th.optional::<u32>("max_len");
        let unidirectional = th.optional::<bool>("unidirectional").unwrap_or(false);
        th.finalize(None)?;
        Ok(FilterConfig {
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
        })
    }
}

impl<'de> Deserialize<'de> for OutputConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let format = th.required::<String>("format")?;
        let path = th.required::<String>("path").map(PathBuf::from)?;
        let compress_payload = th.optional::<bool>("compress_payload").unwrap_or(false);
        th.finalize(None)?;
        Ok(OutputConfig {
            format,
            path,
            compress_payload,
        })
    }
}

impl<'de> Deserialize<'de> for ReplayConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let interface = th.optional::<String>("interface");
        let speed = th.optional::<f64>("speed").unwrap_or(1.0);
        th.finalize(None)?;
        Ok(ReplayConfig { interface, speed })
    }
}

// ── File loading ─────────────────────────────────────────────────────────────

impl Config {
    /// Load configuration from a TOML file at `path`.
    ///
    /// # Errors
    /// Returns [`ConfigError`] on I/O failure or TOML parse / deserialise error.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        let mut value = toml_span::parse(&text)?;
        let config = Config::deserialize(&mut value)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.input.is_empty());
        assert!(!config.sort.enabled);
        assert!(config.filter.proto.is_empty());
        assert!(!config.filter.unidirectional);
        assert_eq!(config.replay.speed, 1.0);
    }

    #[test]
    fn test_from_toml_str_parses_correctly() {
        let toml = r#"
[[input]]
path = "captures/*.pcap"

[sort]
enabled = true
slice = "1h"

[filter]
proto = ["tcp", "udp"]
dst_port = ["443", "80"]
src_ip = ["10.0.0.0/8"]

[[output]]
format = "parquet"
path = "out/traffic.parquet"

[replay]
interface = "eth0"
speed = 2.0
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let config = Config::deserialize(&mut value).unwrap();

        assert_eq!(config.input.len(), 1);
        assert_eq!(config.input[0].path, "captures/*.pcap");
        assert!(config.sort.enabled);
        assert_eq!(config.sort.slice.as_deref(), Some("1h"));
        assert_eq!(config.filter.proto, ["tcp", "udp"]);
        assert_eq!(config.filter.dst_port, ["443", "80"]);
        assert_eq!(config.output.len(), 1);
        assert_eq!(config.output[0].format, "parquet");
        assert_eq!(config.replay.speed, 2.0);
        assert_eq!(config.replay.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_empty_toml_produces_default_config() {
        let mut value = toml_span::parse("").unwrap();
        let config = Config::deserialize(&mut value).unwrap();
        assert!(config.input.is_empty());
        assert!(!config.sort.enabled);
    }

    #[test]
    fn test_unknown_keys_error() {
        let toml = r#"
[sort]
enabled = true
bogus_key = "oops"
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let result = Config::deserialize(&mut value);
        assert!(result.is_err());
    }
}
