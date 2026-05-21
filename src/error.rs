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
}
