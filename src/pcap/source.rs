//! Where packets are read from.
//!
//! [`PacketSource`] names a packet input — a file on disk or standard input —
//! and opens it as a plain [`Read`] stream. Parsing is then done by the
//! generic [`open_reader`](super::open_reader) family, which accepts any
//! `R: Read`, so callers with other inputs (an in-memory buffer, a socket,
//! a decompressor) can bypass this type entirely.
//!
//! # Seekability
//! Standard input is a one-shot, non-seekable stream. Operations that need
//! random access (`sort`'s second pass) or that read the input twice (the
//! `--min-flow-packets` pre-scan) must check [`PacketSource::is_rereadable`]
//! and refuse stdin.

use std::fmt;
use std::path::{Path, PathBuf};

/// Command-line spelling of "read from standard input".
pub const STDIN_ARG: &str = "-";

/// A packet input: a file path or standard input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketSource {
    /// A PCAP / PCAPng file on disk.
    File(PathBuf),
    /// Standard input (e.g. `tcpdump -w - | pcap-toolkit stats -`).
    Stdin,
}

impl PacketSource {
    /// Interpret a command-line argument: [`STDIN_ARG`] (`-`) selects
    /// [`PacketSource::Stdin`]; anything else is a file path.
    ///
    /// The `From<&Path>` conversions never do this mapping — a library caller
    /// passing `Path::new("-")` gets a file literally named `-`.
    pub fn from_arg(arg: &Path) -> Self {
        if arg.as_os_str() == STDIN_ARG {
            Self::Stdin
        } else {
            Self::File(arg.to_owned())
        }
    }

    /// `true` for [`PacketSource::Stdin`].
    pub fn is_stdin(&self) -> bool {
        matches!(self, Self::Stdin)
    }

    /// Whether the input can be opened more than once and seeked.
    pub fn is_rereadable(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// The file path, or `None` for stdin.
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Self::File(path) => Some(path),
            Self::Stdin => None,
        }
    }
}

impl fmt::Display for PacketSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(formatter, "{}", path.display()),
            Self::Stdin => formatter.write_str("<stdin>"),
        }
    }
}

impl From<&Path> for PacketSource {
    fn from(path: &Path) -> Self {
        Self::File(path.to_owned())
    }
}

impl From<&PathBuf> for PacketSource {
    fn from(path: &PathBuf) -> Self {
        Self::File(path.clone())
    }
}

impl From<PathBuf> for PacketSource {
    fn from(path: PathBuf) -> Self {
        Self::File(path)
    }
}

impl From<&PacketSource> for PacketSource {
    fn from(source: &PacketSource) -> Self {
        source.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_arg_dash_is_stdin() {
        assert_eq!(PacketSource::from_arg(Path::new("-")), PacketSource::Stdin);
    }

    #[test]
    fn test_from_arg_path_is_file() {
        for arg in ["capture.pcap", "./-", "--", "-x", "/tmp/-"] {
            assert_eq!(
                PacketSource::from_arg(Path::new(arg)),
                PacketSource::File(PathBuf::from(arg)),
                "{arg} must be treated as a file"
            );
        }
    }

    #[test]
    fn test_from_path_never_maps_to_stdin() {
        assert_eq!(
            PacketSource::from(Path::new("-")),
            PacketSource::File(PathBuf::from("-"))
        );
        assert_eq!(
            PacketSource::from(PathBuf::from("-")),
            PacketSource::File(PathBuf::from("-"))
        );
        assert_eq!(
            PacketSource::from(&PathBuf::from("a.pcap")),
            PacketSource::File(PathBuf::from("a.pcap"))
        );
        assert_eq!(
            PacketSource::from(&PacketSource::Stdin),
            PacketSource::Stdin
        );
    }

    #[test]
    fn test_predicates_and_accessors() {
        let file = PacketSource::File(PathBuf::from("a.pcap"));
        assert!(!file.is_stdin());
        assert!(file.is_rereadable());
        assert_eq!(file.as_path(), Some(Path::new("a.pcap")));

        assert!(PacketSource::Stdin.is_stdin());
        assert!(!PacketSource::Stdin.is_rereadable());
        assert_eq!(PacketSource::Stdin.as_path(), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(
            PacketSource::File(PathBuf::from("/data/a.pcap")).to_string(),
            "/data/a.pcap"
        );
        assert_eq!(PacketSource::Stdin.to_string(), "<stdin>");
    }
}
