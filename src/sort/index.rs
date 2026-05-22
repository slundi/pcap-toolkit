//! Packet index types for two-pass chronological sorting.
//!
//! [`PacketIndex`] is exactly 20 bytes — a minimal record that lets the second
//! pass seek directly to each packet without buffering payloads.
//!
//! [`IndexStore`] abstracts over in-memory and on-disk storage so the first
//! pass can switch modes transparently.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::SortError;

// ── PacketIndex ──────────────────────────────────────────────────────────────

/// Minimal per-packet record built during the first pass.
///
/// | Field          | Size | Description                                   |
/// |----------------|------|-----------------------------------------------|
/// | `timestamp_ns` | 8 B  | Nanoseconds since the Unix epoch              |
/// | `byte_offset`  | 8 B  | File position of the 16-byte record header    |
/// | `caplen`       | 4 B  | Captured packet length (payload only)         |
///
/// Total: **20 bytes** per packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketIndex {
    /// Packet timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Byte offset of the 16-byte PCAP record header in the source file.
    pub byte_offset: u64,
    /// Captured packet length (bytes of payload, not including the record header).
    pub caplen: u32,
}

impl PacketIndex {
    pub(crate) const SIZE: usize = 20;

    /// Serialise to 20 little-endian bytes.
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        buf[8..16].copy_from_slice(&self.byte_offset.to_le_bytes());
        buf[16..20].copy_from_slice(&self.caplen.to_le_bytes());
        buf
    }

    /// Deserialise from 20 little-endian bytes.
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Self {
        Self {
            timestamp_ns: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            byte_offset: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            caplen: u32::from_le_bytes(b[16..20].try_into().unwrap()),
        }
    }
}

// ── FilePacketIndex ──────────────────────────────────────────────────────────

/// A [`PacketIndex`] entry annotated with the index of its source file.
///
/// Used in the multi-file merge path so the second pass can seek into the
/// correct input file for each packet.
#[derive(Debug, Clone, Copy)]
pub struct FilePacketIndex {
    pub entry: PacketIndex,
    /// Index into the `inputs` slice passed to [`crate::sort::sort_files`].
    pub file_id: usize,
}

// ── IndexStore ───────────────────────────────────────────────────────────────

/// Storage backend for the first-pass packet index.
pub enum IndexStore {
    /// In-memory vector — fast path for captures that fit comfortably in RAM.
    Memory(Vec<PacketIndex>),
    /// On-disk sidecar file — for TB-scale inputs where the index itself may be
    /// large (≈ 20 MB per 1 M packets).
    Disk {
        writer: BufWriter<File>,
        path: PathBuf,
        count: u64,
    },
}

impl IndexStore {
    /// Create an in-memory store.
    pub fn memory() -> Self {
        IndexStore::Memory(Vec::new())
    }

    /// Create an on-disk store backed by a file at `sidecar_path`.
    ///
    /// # Errors
    /// Returns [`SortError::Io`] if the sidecar file cannot be created.
    pub fn disk(sidecar_path: &Path) -> Result<Self, SortError> {
        let file = File::create(sidecar_path)?;
        Ok(IndexStore::Disk {
            writer: BufWriter::with_capacity(64 * 1024, file),
            path: sidecar_path.to_owned(),
            count: 0,
        })
    }

    /// Append one [`PacketIndex`] record.
    ///
    /// # Errors
    /// Returns [`SortError::Io`] on write failure (disk mode only).
    pub fn push(&mut self, entry: PacketIndex) -> Result<(), SortError> {
        match self {
            IndexStore::Memory(v) => {
                v.push(entry);
                Ok(())
            }
            IndexStore::Disk { writer, count, .. } => {
                writer.write_all(&entry.to_bytes())?;
                *count += 1;
                Ok(())
            }
        }
    }

    /// Return the path of the on-disk sidecar file, if any.
    pub fn sidecar_path(&self) -> Option<&Path> {
        match self {
            IndexStore::Disk { path, .. } => Some(path),
            IndexStore::Memory(_) => None,
        }
    }

    /// Flush any buffered writes, sort all entries by `timestamp_ns`, and
    /// return the result as an owned `Vec<PacketIndex>`.
    ///
    /// The on-disk sidecar file is **not** deleted here; the caller is
    /// responsible for cleanup.
    ///
    /// # Errors
    /// Returns [`SortError::Io`] on flush or read failure.
    pub fn into_sorted(self) -> Result<Vec<PacketIndex>, SortError> {
        match self {
            IndexStore::Memory(mut v) => {
                v.sort_unstable_by_key(|e| e.timestamp_ns);
                Ok(v)
            }
            IndexStore::Disk {
                mut writer,
                path,
                count,
            } => {
                writer.flush()?;
                drop(writer);
                let mut entries = read_disk_index(&path, count)?;
                entries.sort_unstable_by_key(|e| e.timestamp_ns);
                Ok(entries)
            }
        }
    }
}

/// Read all [`PacketIndex`] records back from a sidecar file.
fn read_disk_index(path: &Path, expected: u64) -> Result<Vec<PacketIndex>, SortError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut entries = Vec::with_capacity(expected as usize);
    let mut buf = [0u8; PacketIndex::SIZE];
    loop {
        match reader.read_exact(&mut buf) {
            Ok(()) => entries.push(PacketIndex::from_bytes(&buf)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(SortError::Io(e)),
        }
    }
    Ok(entries)
}

// ── Helpers used by the second pass ─────────────────────────────────────────

/// Derive the `.idx` sidecar path by appending `.idx` to the input path.
///
/// # Examples
/// ```
/// assert_eq!(
///     pcap_toolkit::sort::index::sidecar_path(std::path::Path::new("/tmp/traffic.pcap")),
///     std::path::PathBuf::from("/tmp/traffic.pcap.idx"),
/// );
/// ```
pub fn sidecar_path(input: &Path) -> PathBuf {
    let name = input
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    input.with_file_name(format!("{name}.idx"))
}

/// Seek `file` to `offset`, read the 16-byte PCAP record header to recover
/// `origlen`, then read `caplen` bytes of packet data.
///
/// Returns `(origlen, packet_data)`.
///
/// # Errors
/// Returns [`SortError::Io`] on seek or read failure.
pub fn read_packet_at(
    file: &mut File,
    offset: u64,
    caplen: u32,
    big_endian: bool,
) -> Result<(u32, Vec<u8>), SortError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut hdr = [0u8; 16];
    file.read_exact(&mut hdr)?;
    let origlen = if big_endian {
        u32::from_be_bytes(hdr[12..16].try_into().unwrap())
    } else {
        u32::from_le_bytes(hdr[12..16].try_into().unwrap())
    };
    let mut data = vec![0u8; caplen as usize];
    file.read_exact(&mut data)?;
    Ok((origlen, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_index_roundtrip() {
        let idx = PacketIndex {
            timestamp_ns: 1_700_000_000_123_456_789,
            byte_offset: 4096,
            caplen: 1500,
        };
        let bytes = idx.to_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(PacketIndex::from_bytes(&bytes), idx);
    }

    #[test]
    fn test_memory_store_sorts_by_timestamp() {
        let mut store = IndexStore::memory();
        for (ts, off) in [(3000u64, 300u64), (1000, 100), (2000, 200)] {
            store
                .push(PacketIndex {
                    timestamp_ns: ts,
                    byte_offset: off,
                    caplen: 60,
                })
                .unwrap();
        }
        let sorted = store.into_sorted().unwrap();
        assert_eq!(
            sorted.iter().map(|e| e.timestamp_ns).collect::<Vec<_>>(),
            [1000, 2000, 3000]
        );
    }

    #[test]
    fn test_disk_store_roundtrip() {
        let path = std::env::temp_dir().join("pcap_toolkit_test_index.idx");
        let mut store = IndexStore::disk(&path).unwrap();
        for (ts, off) in [(300u64, 30u64), (100, 10), (200, 20)] {
            store
                .push(PacketIndex {
                    timestamp_ns: ts,
                    byte_offset: off,
                    caplen: 42,
                })
                .unwrap();
        }
        let sorted = store.into_sorted().unwrap();
        assert_eq!(
            sorted.iter().map(|e| e.timestamp_ns).collect::<Vec<_>>(),
            [100, 200, 300]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_sidecar_path() {
        assert_eq!(
            sidecar_path(Path::new("/tmp/traffic.pcap")),
            PathBuf::from("/tmp/traffic.pcap.idx"),
        );
    }
}
