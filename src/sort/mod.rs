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
use rayon::prelude::*;

use crate::bpf::BpfExpr;
use crate::error::SortError;
use crate::filter::{Filter, PacketMeta};
use crate::transform::{self, TransformOptions};
use index::{FilePacketIndex, IndexStore, PacketIndex, read_packet_at, sidecar_path};
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
    /// Packet-level transformations (truncation, timestamp shift, IP mapping).
    pub transform: TransformOptions,
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
/// Thin wrapper around [`sort_files`] for the common single-input case.
///
/// PCAPng input is not yet supported and returns [`SortError::PcapNgNotSupported`].
///
/// # Errors
/// Returns [`SortError`] on I/O failure, unsupported input format, or
/// invalid slice specification.
pub fn sort_file(input: &Path, opts: &SortOptions) -> Result<SortReport, SortError> {
    sort_files(&[input], opts)
}

/// Sort and merge one or more input files chronologically.
///
/// First passes are run in **parallel** across all inputs using Rayon; the
/// resulting per-file indexes are merged and sorted by timestamp before a
/// single sequential second pass writes the output.
///
/// All input files must share the same link-layer type; if they differ
/// [`SortError::IncompatibleLinkType`] is returned.
///
/// # Errors
/// Returns [`SortError`] on I/O failure, unsupported input format,
/// incompatible link types, or invalid slice specification.
pub fn sort_files(inputs: &[&Path], opts: &SortOptions) -> Result<SortReport, SortError> {
    if inputs.is_empty() {
        return Ok(SortReport {
            packets_written: 0,
            files_written: vec![],
        });
    }

    // ── Parallel first pass ───────────────────────────────────────────────
    let results: Vec<Result<(GlobalHeader, IndexStore), SortError>> = inputs
        .par_iter()
        .map(|p| first_pass(p, opts.on_disk, &opts.filter, opts.bpf_filter.as_ref()))
        .collect();

    let mut headers_and_stores: Vec<(GlobalHeader, IndexStore)> = Vec::with_capacity(inputs.len());
    let mut first_err: Option<SortError> = None;
    for r in results {
        match r {
            Ok(hs) => headers_and_stores.push(hs),
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    if let Some(e) = first_err {
        for (_, store) in &headers_and_stores {
            if let Some(p) = store.sidecar_path() {
                let _ = std::fs::remove_file(p);
            }
        }
        return Err(e);
    }

    // ── Link-type compatibility check ─────────────────────────────────────
    let reference_hdr = headers_and_stores[0].0;
    for (i, (hdr, _)) in headers_and_stores.iter().enumerate().skip(1) {
        if hdr.network != reference_hdr.network {
            // Clean up any on-disk sidecar files before returning.
            for (_, store) in &headers_and_stores {
                if let Some(p) = store.sidecar_path() {
                    let _ = std::fs::remove_file(p);
                }
            }
            return Err(SortError::IncompatibleLinkType {
                path: inputs[i].to_owned(),
                first: reference_hdr.network,
                found: hdr.network,
            });
        }
    }

    // ── Merge per-file indexes ────────────────────────────────────────────
    let mut merged: Vec<FilePacketIndex> = Vec::new();
    for (file_id, (_, store)) in headers_and_stores.into_iter().enumerate() {
        let sidecar = store.sidecar_path().map(Path::to_owned);
        let entries = store.into_sorted()?;
        for entry in entries {
            merged.push(FilePacketIndex { entry, file_id });
        }
        if let Some(ref p) = sidecar {
            let _ = std::fs::remove_file(p);
        }
    }

    // Stable sort with tie-break on (file_id, byte_offset) so packets with
    // identical timestamps keep their original capture order.
    merged.sort_by_key(|e| (e.entry.timestamp_ns, e.file_id, e.entry.byte_offset));

    second_pass_multi(inputs, reference_hdr, &merged, opts)
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

/// Scan a single input file to build its packet index and capture the global header.
///
/// When `filter` / `bpf` are active (7.4 pre-filter) packets that cannot
/// match are skipped from the index entirely, reducing second-pass seeks.
fn first_pass(
    input: &Path,
    on_disk: bool,
    filter: &Filter,
    bpf: Option<&BpfExpr>,
) -> Result<(GlobalHeader, IndexStore), SortError> {
    let magic = read_magic(input)?;
    if u32::from_le_bytes(magic) == 0x0a0d_0d0a {
        return Err(SortError::PcapNgNotSupported);
    }

    let file = File::open(input)?;
    let mut reader =
        LegacyPcapReader::new(BUF_SIZE, file).map_err(|e| SortError::Parse(format!("{e:?}")))?;

    let sidecar = on_disk.then(|| sidecar_path(input));
    let store = match &sidecar {
        Some(p) => IndexStore::disk(p)?,
        None => IndexStore::memory(),
    };

    first_pass_inner(&mut reader, store, filter, bpf).inspect_err(|_| {
        if let Some(p) = &sidecar {
            let _ = std::fs::remove_file(p);
        }
    })
}

fn first_pass_inner<R: std::io::Read>(
    reader: &mut LegacyPcapReader<R>,
    mut store: IndexStore,
    filter: &Filter,
    bpf: Option<&BpfExpr>,
) -> Result<(GlobalHeader, IndexStore), SortError> {
    let mut global_hdr: Option<GlobalHeader> = None;
    let mut file_offset: u64 = 0;
    let has_filter = !filter.is_empty() || bpf.is_some();

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

                        // 7.4 pre-filter: skip packets that cannot match the
                        // active filter, avoiding unnecessary second-pass seeks.
                        let should_index = if has_filter {
                            let meta = PacketMeta::from_packet(timestamp_ns, pkt.caplen, pkt.data);
                            let structured = filter.is_empty() || filter.matches(&meta);
                            let bpf_ok = bpf.is_none_or(|b| b.eval(&meta));
                            structured && bpf_ok
                        } else {
                            true
                        };

                        if should_index {
                            store.push(PacketIndex {
                                timestamp_ns,
                                byte_offset: file_offset,
                                caplen: pkt.caplen,
                            })?;
                        }

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

// ── Second pass ───────────────────────────────────────────────────────────────

/// Multi-file second pass: open all source files, seek-and-stream packets in
/// sorted order, apply transforms, and write output.
fn second_pass_multi(
    inputs: &[&Path],
    header: GlobalHeader,
    sorted: &[FilePacketIndex],
    opts: &SortOptions,
) -> Result<SortReport, SortError> {
    let mut src_files: Vec<File> = inputs
        .iter()
        .map(|p| File::open(p).map_err(SortError::Io))
        .collect::<Result<_, _>>()?;

    let big_endian = header.is_big_endian();
    let mut writer = SlicedWriter::new(opts.output.clone(), header, opts.slice_secs);

    let ts_delta: i64 = if let Some(target_ns) = opts.transform.timestamp_start_ns {
        sorted
            .first()
            .map(|p| target_ns as i64 - p.entry.timestamp_ns as i64)
            .unwrap_or(0)
    } else {
        0
    };
    let has_transform = !opts.transform.is_empty();
    // Second-pass filter is kept for correctness when pre-filter was not
    // active (no filter) or when the caller bypasses sort_files directly.
    let has_filter = !opts.filter.is_empty() || opts.bpf_filter.is_some();

    for entry in sorted {
        let (origlen, mut data) = read_packet_at(
            &mut src_files[entry.file_id],
            entry.entry.byte_offset,
            entry.entry.caplen,
            big_endian,
        )?;

        if has_filter {
            let meta = PacketMeta::from_packet(entry.entry.timestamp_ns, entry.entry.caplen, &data);
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

        let (ts, caplen, new_origlen) = if has_transform {
            transform::apply(
                &mut data,
                entry.entry.timestamp_ns,
                ts_delta,
                origlen,
                &opts.transform,
            )
        } else {
            (entry.entry.timestamp_ns, data.len() as u32, origlen)
        };

        writer.write_packet(ts, caplen, new_origlen, &data)?;
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
