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

/// RAII handle for an on-disk sidecar file.
///
/// Removes the file on drop unless [`disarm`](Self::disarm) is called. This
/// guarantees cleanup on every exit path — including panics, `?` early
/// returns, and signal-induced unwinding — so a half-finished sort no longer
/// leaks gigabytes of `.idx` files.
pub struct SidecarGuard {
    path: Option<PathBuf>,
}

impl SidecarGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Borrow the path of the file being guarded.
    ///
    /// # Panics
    /// Panics if the guard has been disarmed.
    pub fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("SidecarGuard accessed after disarm")
    }

    /// Disarm the guard so the file is *not* removed on drop and return the
    /// owned path. Useful when caller code wants to keep the sidecar around.
    pub fn disarm(mut self) -> PathBuf {
        self.path.take().expect("SidecarGuard already disarmed")
    }
}

impl Drop for SidecarGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Storage backend for the first-pass packet index.
pub enum IndexStore {
    /// In-memory vector — fast path for captures that fit comfortably in RAM.
    Memory(Vec<PacketIndex>),
    /// On-disk sidecar file — for TB-scale inputs where the index itself may be
    /// large (≈ 20 MB per 1 M packets).
    Disk {
        writer: BufWriter<File>,
        guard: SidecarGuard,
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
    /// The returned store owns a [`SidecarGuard`] that deletes the file when
    /// the store is dropped, regardless of whether the sort completes cleanly.
    ///
    /// # Errors
    /// Returns [`SortError::Io`] if the sidecar file cannot be created.
    pub fn disk(sidecar_path: &Path) -> Result<Self, SortError> {
        let file = File::create(sidecar_path)?;
        Ok(IndexStore::Disk {
            writer: BufWriter::with_capacity(64 * 1024, file),
            guard: SidecarGuard::new(sidecar_path.to_owned()),
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
            IndexStore::Disk { guard, .. } => Some(guard.path()),
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
                // Stable sort on (timestamp_ns, byte_offset): equal timestamps
                // retain capture order so retransmission analysis stays valid.
                v.sort_by_key(|e| (e.timestamp_ns, e.byte_offset));
                Ok(v)
            }
            IndexStore::Disk {
                mut writer,
                guard,
                count,
            } => {
                writer.flush()?;
                drop(writer);
                let mut entries = read_disk_index(guard.path(), count)?;
                entries.sort_by_key(|e| (e.timestamp_ns, e.byte_offset));
                // `guard` is dropped at end of scope, removing the sidecar.
                drop(guard);
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

/// Hard ceiling on `caplen` accepted by [`read_packet_at`].
///
/// PCAP snaplen is a `u32`, so a corrupted index can request a 4 GiB allocation
/// per packet. We cap at 256 KiB — well above the largest realistic frame
/// (IPv6 jumbograms top out at 65535 bytes; 9000-byte jumbos are typical).
pub const MAX_CAPLEN: u32 = 256 * 1024;

/// Seek `reader` to `offset`, read the 16-byte PCAP record header to recover
/// `origlen`, then read `caplen` bytes of packet data.
///
/// Generic over any seekable reader (a [`File`], a `BufReader<File>`, an
/// in-memory `Cursor<Vec<u8>>`, …). Monomorphised, so there is no dynamic
/// dispatch on the per-packet hot path.
///
/// Returns `(origlen, packet_data)`.
///
/// # Errors
/// - [`SortError::CaplenTooLarge`] if `caplen` exceeds [`MAX_CAPLEN`].
/// - [`SortError::Io`] on seek or read failure.
pub fn read_packet_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    caplen: u32,
    big_endian: bool,
) -> Result<(u32, Vec<u8>), SortError> {
    if caplen > MAX_CAPLEN {
        return Err(SortError::CaplenTooLarge {
            caplen,
            max: MAX_CAPLEN,
        });
    }
    reader.seek(SeekFrom::Start(offset))?;
    let mut hdr = [0u8; 16];
    reader.read_exact(&mut hdr)?;
    let origlen = if big_endian {
        u32::from_be_bytes(hdr[12..16].try_into().unwrap())
    } else {
        u32::from_le_bytes(hdr[12..16].try_into().unwrap())
    };
    let mut data = vec![0u8; caplen as usize];
    reader.read_exact(&mut data)?;
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
        // Defensive: ensure no stale file from a previous run.
        let _ = std::fs::remove_file(&path);
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
        // SidecarGuard drops with the store at end of into_sorted — the
        // sidecar file must no longer exist.
        assert!(
            !path.exists(),
            "sidecar should be auto-removed by SidecarGuard"
        );
    }

    #[test]
    fn test_sidecar_guard_removes_file_on_drop() {
        // Simulate abnormal termination: push some records, then drop the
        // store without calling into_sorted(). The .idx file must be gone.
        let path = std::env::temp_dir().join("pcap_toolkit_test_drop_cleanup.idx");
        let _ = std::fs::remove_file(&path);
        {
            let mut store = IndexStore::disk(&path).unwrap();
            store
                .push(PacketIndex {
                    timestamp_ns: 1,
                    byte_offset: 0,
                    caplen: 1,
                })
                .unwrap();
            assert!(path.exists(), "sidecar must exist while store is live");
            // store goes out of scope here — SidecarGuard::drop fires.
        }
        assert!(
            !path.exists(),
            "sidecar must be removed on store drop (abnormal-termination guard)"
        );
    }

    #[test]
    fn test_sidecar_guard_disarm_keeps_file() {
        // Disarming the guard transfers cleanup responsibility to the caller.
        let path = std::env::temp_dir().join("pcap_toolkit_test_disarm.idx");
        let _ = std::fs::remove_file(&path);
        let guard = SidecarGuard::new(path.clone());
        std::fs::write(&path, b"x").unwrap();
        let returned = guard.disarm();
        assert_eq!(returned, path);
        assert!(
            path.exists(),
            "disarmed guard must not remove the file on drop"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_memory_store_stable_on_equal_timestamps() {
        // Packets with the same timestamp must keep their capture order
        // (tie-break is byte_offset, which is monotonic per file).
        let mut store = IndexStore::memory();
        for (ts, off) in [
            (1000u64, 10u64),
            (1000, 20),
            (1000, 30),
            (500, 40),
            (1000, 50),
        ] {
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
            sorted.iter().map(|e| e.byte_offset).collect::<Vec<_>>(),
            [40, 10, 20, 30, 50]
        );
    }

    #[test]
    fn test_read_packet_at_rejects_oversized_caplen() {
        // Create a tiny file — content doesn't matter; we should error before
        // any read on the oversized caplen.
        let path = std::env::temp_dir().join("pcap_toolkit_test_caplen.bin");
        std::fs::write(&path, b"").unwrap();
        let mut file = File::open(&path).unwrap();
        let err = read_packet_at(&mut file, 0, MAX_CAPLEN + 1, false).unwrap_err();
        assert!(matches!(
            err,
            crate::error::SortError::CaplenTooLarge { caplen, max }
                if caplen == MAX_CAPLEN + 1 && max == MAX_CAPLEN
        ));
        let _ = std::fs::remove_file(&path);
    }

    /// Build a 16-byte PCAP record header with the given `origlen` followed by
    /// `payload`, prefixed by `pad` filler bytes.
    fn record_bytes(pad: usize, origlen: u32, payload: &[u8], big_endian: bool) -> Vec<u8> {
        let mut buf = vec![0xAAu8; pad];
        buf.extend_from_slice(&[0u8; 12]); // ts_sec, ts_frac, incl_len (unused here)
        if big_endian {
            buf.extend_from_slice(&origlen.to_be_bytes());
        } else {
            buf.extend_from_slice(&origlen.to_le_bytes());
        }
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_read_packet_at_in_memory_cursor_le() {
        let payload = [1u8, 2, 3, 4, 5];
        let bytes = record_bytes(24, 1500, &payload, false);
        let mut cursor = std::io::Cursor::new(bytes);
        let (origlen, data) = read_packet_at(&mut cursor, 24, payload.len() as u32, false).unwrap();
        assert_eq!(origlen, 1500);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_read_packet_at_in_memory_cursor_be() {
        let payload = [9u8, 8, 7];
        let bytes = record_bytes(0, 0x0102_0304, &payload, true);
        let mut cursor = std::io::Cursor::new(bytes);
        let (origlen, data) = read_packet_at(&mut cursor, 0, payload.len() as u32, true).unwrap();
        assert_eq!(origlen, 0x0102_0304);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_read_packet_at_truncated_input_is_io_error() {
        // Header present but payload shorter than caplen → UnexpectedEof.
        let bytes = record_bytes(0, 64, &[1, 2], false);
        let mut cursor = std::io::Cursor::new(bytes);
        let err = read_packet_at(&mut cursor, 0, 10, false).unwrap_err();
        assert!(matches!(err, crate::error::SortError::Io(_)));
    }

    #[test]
    fn test_sidecar_path() {
        assert_eq!(
            sidecar_path(Path::new("/tmp/traffic.pcap")),
            PathBuf::from("/tmp/traffic.pcap.idx"),
        );
    }
}
