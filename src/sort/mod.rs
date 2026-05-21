//! Two-pass chronological sorting for legacy PCAP files.
//!
//! ## Algorithm
//!
//! **First pass** — scan the input file sequentially, tracking byte offsets.
//! For each packet emit one [`PacketIndex`] record (20 bytes). The index is
//! held in memory (default) or streamed to a `.idx` sidecar file (`--on-disk`).
//!
//! **Second pass** — sort the index by `timestamp_ns`, then seek-and-stream
//! packets in chronological order into one or more output PCAP files.
//! Time-slicing (`--slice`) splits output into separate files at regular
//! intervals.

pub mod index;
mod writer;

use std::fs::File;
use std::path::{Path, PathBuf};

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};

use crate::bpf::BpfExpr;
use crate::error::SortError;
use crate::filter::{Filter, PacketMeta};
use index::{IndexStore, PacketIndex, read_packet_at, sidecar_path};
use writer::{GlobalHeader, SlicedWriter};

const BUF_SIZE: usize = 65536;

// ── Public types ─────────────────────────────────────────────────────────────

/// Options for [`sort_file`].
#[derive(Debug, Default)]
pub struct SortOptions {
    /// Destination: a file path when no slicing, a directory path when slicing.
    pub output: PathBuf,
    /// Time-slice interval in seconds. `None` produces a single output file.
    pub slice_secs: Option<u64>,
    /// When `true`, write the index to a `.idx` sidecar file instead of RAM.
    pub on_disk: bool,
    /// Structured packet filter applied during the second pass.
    pub filter: Filter,
    /// BPF expression filter AND-ed with `filter`. `None` = no BPF filter.
    pub bpf_filter: Option<BpfExpr>,
}

/// Summary returned by [`sort_file`] on success.
#[derive(Debug)]
pub struct SortReport {
    /// Total packets written across all output files.
    pub packets_written: u64,
    /// Paths of output PCAP files, in creation order.
    pub files_written: Vec<PathBuf>,
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Sort `input` chronologically and write the result according to `opts`.
///
/// PCAPng input is not yet supported and returns [`SortError::PcapNgNotSupported`].
///
/// # Errors
/// Returns [`SortError`] on I/O failure, unsupported input format, or
/// invalid slice specification.
pub fn sort_file(input: &Path, opts: &SortOptions) -> Result<SortReport, SortError> {
    let (global_hdr, store) = first_pass(input, opts.on_disk)?;

    // Remember the sidecar path before consuming `store`.
    let sidecar = store.sidecar_path().map(Path::to_owned);

    let sorted_index = store.into_sorted()?;

    let report = second_pass(input, global_hdr, &sorted_index, opts)?;

    // Remove the sidecar file now that sorting is complete.
    if let Some(ref p) = sidecar {
        let _ = std::fs::remove_file(p);
    }

    Ok(report)
}

/// Parse a human-readable slice duration string into seconds.
///
/// Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days).
/// A bare integer is treated as seconds.
///
/// # Errors
/// Returns [`SortError::InvalidSlice`] if the string cannot be parsed.
///
/// # Examples
/// ```
/// use pcap_toolkit::sort::parse_slice;
/// assert_eq!(parse_slice("1h").unwrap(), 3600);
/// assert_eq!(parse_slice("30m").unwrap(), 1800);
/// assert_eq!(parse_slice("1d").unwrap(), 86400);
/// assert_eq!(parse_slice("120").unwrap(), 120);
/// ```
pub fn parse_slice(s: &str) -> Result<u64, SortError> {
    let (digits, multiplier) = if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86400)
    } else {
        (s, 1)
    };

    digits
        .parse::<u64>()
        .map(|n| n * multiplier)
        .map_err(|_| SortError::InvalidSlice(s.to_owned()))
}

// ── First pass ───────────────────────────────────────────────────────────────

/// Scan the input file to build the packet index and capture the global header.
///
/// Returns `(GlobalHeader, IndexStore)`.
fn first_pass(input: &Path, on_disk: bool) -> Result<(GlobalHeader, IndexStore), SortError> {
    // Detect format before opening the streaming reader.
    let magic = read_magic(input)?;
    let u32_magic = u32::from_le_bytes(magic);
    if u32_magic == 0x0a0d_0d0a {
        return Err(SortError::PcapNgNotSupported);
    }

    let file = File::open(input)?;
    let mut reader =
        LegacyPcapReader::new(BUF_SIZE, file).map_err(|e| SortError::Parse(format!("{e:?}")))?;

    let store = if on_disk {
        IndexStore::disk(&sidecar_path(input))?
    } else {
        IndexStore::memory()
    };

    first_pass_inner(&mut reader, store)
}

fn first_pass_inner<R: std::io::Read>(
    reader: &mut LegacyPcapReader<R>,
    mut store: IndexStore,
) -> Result<(GlobalHeader, IndexStore), SortError> {
    let mut global_hdr: Option<GlobalHeader> = None;
    // Byte offset tracking: starts at 0 and advances by each consumed block.
    let mut file_offset: u64 = 0;

    loop {
        match reader.next() {
            Ok((consumed, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        global_hdr = Some(GlobalHeader {
                            magic_number: hdr.magic_number,
                            version_major: hdr.version_major,
                            version_minor: hdr.version_minor,
                            thiszone: hdr.thiszone,
                            sigfigs: hdr.sigfigs,
                            snaplen: hdr.snaplen,
                            network: hdr.network.0,
                        });
                        file_offset += consumed as u64;
                    }
                    PcapBlockOwned::Legacy(pkt) => {
                        let ns_precision = global_hdr
                            .as_ref()
                            .map(|h| h.is_nanosecond())
                            .unwrap_or(false);

                        let timestamp_ns = if ns_precision {
                            u64::from(pkt.ts_sec) * 1_000_000_000 + u64::from(pkt.ts_usec)
                        } else {
                            u64::from(pkt.ts_sec) * 1_000_000_000 + u64::from(pkt.ts_usec) * 1_000
                        };

                        store.push(PacketIndex {
                            timestamp_ns,
                            byte_offset: file_offset,
                            caplen: pkt.caplen,
                        })?;

                        file_offset += consumed as u64;
                    }
                    _ => {
                        file_offset += consumed as u64;
                    }
                }
                reader.consume(consumed);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| SortError::Parse(format!("{e:?}")))?;
            }
            Err(e) => return Err(SortError::Parse(format!("{e:?}"))),
        }
    }

    let hdr = global_hdr.ok_or(SortError::Parse("missing PCAP global header".into()))?;
    Ok((hdr, store))
}

// ── Second pass ──────────────────────────────────────────────────────────────

fn second_pass(
    input: &Path,
    header: GlobalHeader,
    sorted: &[PacketIndex],
    opts: &SortOptions,
) -> Result<SortReport, SortError> {
    let mut src = File::open(input)?;
    let big_endian = header.is_big_endian();

    let mut writer = SlicedWriter::new(opts.output.clone(), header, opts.slice_secs);

    let has_filter = !opts.filter.is_empty() || opts.bpf_filter.is_some();
    for entry in sorted {
        let (origlen, data) =
            read_packet_at(&mut src, entry.byte_offset, entry.caplen, big_endian)?;
        if has_filter {
            let meta = PacketMeta::from_packet(entry.timestamp_ns, entry.caplen, &data);
            let structured_pass = opts.filter.is_empty() || opts.filter.matches(&meta);
            let bpf_pass = opts
                .bpf_filter
                .as_ref()
                .map(|b| b.eval(&meta))
                .unwrap_or(true);
            if !structured_pass || !bpf_pass {
                continue;
            }
        }
        writer.write_packet(entry.timestamp_ns, entry.caplen, origlen, &data)?;
    }

    let (files_written, packets_written) = writer.finish()?;
    Ok(SortReport {
        packets_written,
        files_written,
    })
}

// ── Helper ───────────────────────────────────────────────────────────────────

fn read_magic(path: &Path) -> Result<[u8; 4], SortError> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    let mut f = File::open(path)?;
    f.read_exact(&mut magic)?;
    Ok(magic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_slice_hours() {
        assert_eq!(parse_slice("1h").unwrap(), 3600);
        assert_eq!(parse_slice("2h").unwrap(), 7200);
    }

    #[test]
    fn test_parse_slice_minutes() {
        assert_eq!(parse_slice("30m").unwrap(), 1800);
    }

    #[test]
    fn test_parse_slice_days() {
        assert_eq!(parse_slice("1d").unwrap(), 86400);
    }

    #[test]
    fn test_parse_slice_seconds_explicit() {
        assert_eq!(parse_slice("120s").unwrap(), 120);
    }

    #[test]
    fn test_parse_slice_bare_number() {
        assert_eq!(parse_slice("3600").unwrap(), 3600);
    }

    #[test]
    fn test_parse_slice_invalid() {
        assert!(parse_slice("abc").is_err());
        assert!(parse_slice("").is_err());
        assert!(parse_slice("1x").is_err());
    }
}
