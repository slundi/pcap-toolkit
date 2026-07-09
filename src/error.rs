//! Custom error types for pcap-toolkit library code.

use thiserror::Error;

/// Errors produced by the PCAP reader.
#[derive(Debug, Error)]
pub enum PcapError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PCAP parse error: {0}")]
    Parse(String),

    #[error("unsupported link type: {0}")]
    UnsupportedLinkType(u32),
}

/// Errors produced by the config loader.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error reading config: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(toml_span::DeserError),
}

impl From<toml_span::DeserError> for ConfigError {
    fn from(e: toml_span::DeserError) -> Self {
        ConfigError::Toml(e)
    }
}

impl From<toml_span::Error> for ConfigError {
    fn from(e: toml_span::Error) -> Self {
        ConfigError::Toml(toml_span::DeserError::from(e))
    }
}

/// Errors produced by the structured data exporter.
#[derive(Debug, Error)]
pub enum ExportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PCAP parse error: {0}")]
    Parse(String),

    #[error("JSON serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),

    #[error("Avro error: {0}")]
    Avro(#[from] apache_avro::Error),

    #[error("unsupported export format '{0}': expected json, parquet, or avro")]
    UnknownFormat(String),

    #[error(
        "STDOUT export supports the JSON format only; parquet and avro require a file path (use --output PATH)"
    )]
    StdoutNotJson,

    #[error("export producer thread panicked unexpectedly")]
    ThreadPanic,
}

/// Errors produced by the live replay engine.
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("unknown interface '{0}': not found in /sys/class/net/")]
    UnknownInterface(String),

    #[error(
        "invalid interface name '{0}': only ASCII letters, digits, '.', '_', and '-' are allowed"
    )]
    InvalidInterface(String),

    #[error("PCAP parse error: {0}")]
    PcapParse(String),

    #[error("live replay is not supported on this platform (Linux only)")]
    NotSupported,
}

/// Errors produced by the two-pass sorter.
#[derive(Debug, Error)]
pub enum SortError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PCAP parse error: {0}")]
    Parse(String),

    #[error("PCAPng input is not supported for sorting; use `info` or `stats` instead")]
    PcapNgNotSupported,

    #[error("invalid slice duration '{0}': expected e.g. '1h', '30m', '1d', or seconds")]
    InvalidSlice(String),

    #[error(
        "incompatible link types: first file uses {first}, \
         file '{path}' uses {found} — all inputs must share the same link type"
    )]
    IncompatibleLinkType {
        path: std::path::PathBuf,
        first: i32,
        found: i32,
    },

    #[error("packet caplen {caplen} exceeds the {max}-byte sanity limit (corrupt index?)")]
    CaplenTooLarge { caplen: u32, max: u32 },
}
