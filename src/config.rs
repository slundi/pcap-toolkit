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

    /// Packet-level transformation options.
    pub transform: TransformConfig,

    /// Structured data export options.
    pub export: ExportConfig,

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
    /// When `true`, the entire filter result is inverted.
    pub negate: bool,

    /// Additional filter rules chained after the base body.
    pub rules: Vec<FilterRuleConfig>,

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

/// A single rule entry within `[[filter.rules]]` in the TOML config.
///
/// The `op` field controls how this rule combines with the accumulated result:
/// `"and"` (default), `"or"`, or `"not"`.
#[derive(Debug, Default)]
pub struct FilterRuleConfig {
    /// Logical operator: `"and"`, `"or"`, or `"not"`.
    pub op: String,
    pub proto: Vec<String>,
    pub src_ip: Vec<String>,
    pub dst_ip: Vec<String>,
    pub ip: Vec<String>,
    pub src_port: Vec<String>,
    pub dst_port: Vec<String>,
    pub port: Vec<String>,
    pub flow_id: Vec<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub tcp_flags: Option<String>,
    pub min_len: Option<u32>,
    pub max_len: Option<u32>,
    pub unidirectional: bool,
}

/// A single per-protocol payload truncation rule (`[[transform.truncate_by_proto]]`).
#[derive(Debug)]
pub struct ProtocolTruncationConfig {
    /// IP protocol name (`"tcp"`, `"udp"`, `"icmp"`) or decimal number (`"6"`).
    pub proto: String,
    /// Maximum payload bytes to keep for this protocol.
    pub max_payload_bytes: u32,
}

/// Packet-level transformation configuration (`[transform]` TOML table).
#[derive(Debug, Default)]
pub struct TransformConfig {
    /// Global maximum payload bytes (per-protocol rules take precedence when set).
    pub max_payload_bytes: Option<u32>,
    /// Shift all timestamps so the capture starts at this datetime (RFC 3339 or ms epoch).
    pub timestamp_start: Option<String>,
    /// IP address replacement rules as `"OLD_IP=NEW_IP"` strings.
    pub replace_ip: Vec<String>,
    /// Per-protocol payload truncation rules.
    pub truncate_by_proto: Vec<ProtocolTruncationConfig>,
}

/// A single output target within `[[export.outputs]]`.
#[derive(Debug)]
pub struct ExportOutputConfig {
    /// Output file path (extension determines format unless `format` is set).
    pub path: PathBuf,

    /// Override output format: `"json"`, `"parquet"`, or `"avro"`.
    pub format: Option<String>,

    /// Apply Zstd compression to payload bytes.
    pub compress_payload: bool,
}

/// Structured data export configuration (`[export]` table in TOML).
#[derive(Debug, Default)]
pub struct ExportConfig {
    /// Multiple output targets (fan-out). Takes precedence over `path`.
    pub outputs: Vec<ExportOutputConfig>,

    /// Legacy single output path (superseded by `[[export.outputs]]`).
    pub path: Option<PathBuf>,

    /// Override output format: `"json"`, `"parquet"`, or `"avro"`.
    pub format: Option<String>,

    /// Apply Zstd compression to payload bytes.
    pub compress_payload: bool,

    /// Compute flow IDs unidirectionally (default: bidirectional).
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
    /// Network interface names for replay (fan-out: each packet sent to all).
    /// Accepts `interfaces = ["eth0", "eth1"]` or legacy `interface = "eth0"`.
    pub interfaces: Vec<String>,

    /// Replay speed multiplier (1.0 = real-time, 2.0 = 2× faster).
    /// Ignored when `pps` is set.
    pub speed: f64,

    /// Fixed replay rate in packets per second.
    /// When set, `speed` is ignored and original inter-packet timing is discarded.
    pub pps: Option<u64>,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            speed: 1.0,
            pps: None,
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
        let transform = th
            .optional::<TransformConfig>("transform")
            .unwrap_or_default();
        let export = th.optional::<ExportConfig>("export").unwrap_or_default();
        let replay = th.optional::<ReplayConfig>("replay").unwrap_or_default();
        th.finalize(None)?;
        Ok(Config {
            input,
            sort,
            filter,
            output,
            transform,
            export,
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
        let negate = th.optional::<bool>("negate").unwrap_or(false);
        let rules = th
            .optional::<Vec<FilterRuleConfig>>("rules")
            .unwrap_or_default();
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
            negate,
            rules,
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

impl<'de> Deserialize<'de> for FilterRuleConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let op = th.optional::<String>("op").unwrap_or_default();
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
        Ok(FilterRuleConfig {
            op,
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

impl<'de> Deserialize<'de> for ProtocolTruncationConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let proto = th.required::<String>("proto")?;
        let max_payload_bytes = th.required::<u32>("max_payload_bytes")?;
        th.finalize(None)?;
        Ok(ProtocolTruncationConfig {
            proto,
            max_payload_bytes,
        })
    }
}

impl<'de> Deserialize<'de> for TransformConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let max_payload_bytes = th.optional::<u32>("max_payload_bytes");
        let timestamp_start = th.optional::<String>("timestamp_start");
        let replace_ip = th.optional::<Vec<String>>("replace_ip").unwrap_or_default();
        let truncate_by_proto = th
            .optional::<Vec<ProtocolTruncationConfig>>("truncate_by_proto")
            .unwrap_or_default();
        th.finalize(None)?;
        Ok(TransformConfig {
            max_payload_bytes,
            timestamp_start,
            replace_ip,
            truncate_by_proto,
        })
    }
}

impl<'de> Deserialize<'de> for ExportOutputConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let path = th.required::<String>("path").map(PathBuf::from)?;
        let format = th.optional::<String>("format");
        let compress_payload = th.optional::<bool>("compress_payload").unwrap_or(false);
        th.finalize(None)?;
        Ok(ExportOutputConfig {
            path,
            format,
            compress_payload,
        })
    }
}

impl<'de> Deserialize<'de> for ExportConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let outputs = th
            .optional::<Vec<ExportOutputConfig>>("outputs")
            .unwrap_or_default();
        let path = th.optional::<String>("path").map(PathBuf::from);
        let format = th.optional::<String>("format");
        let compress_payload = th.optional::<bool>("compress_payload").unwrap_or(false);
        let unidirectional = th.optional::<bool>("unidirectional").unwrap_or(false);
        th.finalize(None)?;
        Ok(ExportConfig {
            outputs,
            path,
            format,
            compress_payload,
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
        // Accept `interfaces = ["eth0", "eth1"]` (preferred) or legacy `interface = "eth0"`.
        let mut interfaces = th.optional::<Vec<String>>("interfaces").unwrap_or_default();
        if interfaces.is_empty() {
            if let Some(single) = th.optional::<String>("interface") {
                interfaces.push(single);
            }
        } else {
            // consume the legacy key so finalize doesn't error on unknown keys
            let _ = th.optional::<String>("interface");
        }
        let speed = th.optional::<f64>("speed").unwrap_or(1.0);
        let pps = th.optional::<u64>("pps");
        th.finalize(None)?;
        Ok(ReplayConfig {
            interfaces,
            speed,
            pps,
        })
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
        assert_eq!(config.replay.interfaces, ["eth0"]);
    }

    #[test]
    fn test_filter_rules_toml() {
        let toml = r#"
[filter]
proto = ["tcp"]

[[filter.rules]]
op = "or"
proto = ["udp"]

[[filter.rules]]
op = "not"
dst_ip = ["10.0.0.0/8"]
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let config = Config::deserialize(&mut value).unwrap();
        assert_eq!(config.filter.proto, ["tcp"]);
        assert_eq!(config.filter.rules.len(), 2);
        assert_eq!(config.filter.rules[0].op, "or");
        assert_eq!(config.filter.rules[0].proto, ["udp"]);
        assert_eq!(config.filter.rules[1].op, "not");
        assert_eq!(config.filter.rules[1].dst_ip, ["10.0.0.0/8"]);
    }

    #[test]
    fn test_filter_negate_toml() {
        let toml = r#"
[filter]
negate = true
proto = ["tcp"]
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let config = Config::deserialize(&mut value).unwrap();
        assert!(config.filter.negate);
        assert_eq!(config.filter.proto, ["tcp"]);
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

    #[test]
    fn test_transform_config_global_truncation() {
        let toml = r#"
[transform]
max_payload_bytes = 256
timestamp_start = "2024-01-01T00:00:00Z"
replace_ip = ["10.0.0.1=192.168.1.1"]
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let config = Config::deserialize(&mut value).unwrap();
        assert_eq!(config.transform.max_payload_bytes, Some(256));
        assert_eq!(
            config.transform.timestamp_start.as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
        assert_eq!(config.transform.replace_ip, ["10.0.0.1=192.168.1.1"]);
        assert!(config.transform.truncate_by_proto.is_empty());
    }

    #[test]
    fn test_transform_config_per_proto_truncation() {
        let toml = r#"
[transform]
max_payload_bytes = 512

[[transform.truncate_by_proto]]
proto = "tcp"
max_payload_bytes = 128

[[transform.truncate_by_proto]]
proto = "udp"
max_payload_bytes = 64
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let config = Config::deserialize(&mut value).unwrap();
        assert_eq!(config.transform.max_payload_bytes, Some(512));
        assert_eq!(config.transform.truncate_by_proto.len(), 2);
        assert_eq!(config.transform.truncate_by_proto[0].proto, "tcp");
        assert_eq!(config.transform.truncate_by_proto[0].max_payload_bytes, 128);
        assert_eq!(config.transform.truncate_by_proto[1].proto, "udp");
        assert_eq!(config.transform.truncate_by_proto[1].max_payload_bytes, 64);
    }

    #[test]
    fn test_transform_config_proto_only_no_global() {
        let toml = r#"
[[transform.truncate_by_proto]]
proto = "17"
max_payload_bytes = 32
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let config = Config::deserialize(&mut value).unwrap();
        assert!(config.transform.max_payload_bytes.is_none());
        assert_eq!(config.transform.truncate_by_proto.len(), 1);
        assert_eq!(config.transform.truncate_by_proto[0].proto, "17");
        assert_eq!(config.transform.truncate_by_proto[0].max_payload_bytes, 32);
    }

    #[test]
    fn test_empty_transform_section() {
        let toml = r#"
[transform]
"#;
        let mut value = toml_span::parse(toml).unwrap();
        let config = Config::deserialize(&mut value).unwrap();
        assert!(config.transform.max_payload_bytes.is_none());
        assert!(config.transform.truncate_by_proto.is_empty());
    }
}
