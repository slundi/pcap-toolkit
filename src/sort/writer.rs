//! PCAP output writer with optional time-sliced output.
//!
//! [`PcapWriter`] writes a valid legacy PCAP file by first emitting the global
//! header (mirrored from the source capture) and then appending packet records.
//!
//! [`SlicedWriter`] wraps [`PcapWriter`] and opens a new output file whenever a
//! packet's timestamp crosses a time-slice boundary.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};

use crate::error::SortError;

// ── GlobalHeader ─────────────────────────────────────────────────────────────

/// Captured fields from the source PCAP global header.
///
/// Used to mirror the header identically on every output chunk so that link
/// type, snap length, and byte-order are preserved.
#[derive(Debug, Clone, Copy)]
pub struct GlobalHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    /// Raw link-type value.
    pub network: i32,
}

impl GlobalHeader {
    /// Returns `true` if the source file used big-endian byte order.
    pub fn is_big_endian(self) -> bool {
        // Big-endian magic values: 0xd4c3b2a1 (usec) and 0x4d3cb2a1 (nsec).
        matches!(self.magic_number, 0xd4c3_b2a1 | 0x4d3c_b2a1)
    }

    /// Returns `true` if the source file used nanosecond timestamp precision.
    pub fn is_nanosecond(self) -> bool {
        matches!(self.magic_number, 0xa1b2_3c4d | 0x4d3c_b2a1)
    }

    /// Serialise to 24 bytes, preserving the source byte order.
    pub fn to_bytes(self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        if self.is_big_endian() {
            buf[0..4].copy_from_slice(&self.magic_number.to_be_bytes());
            buf[4..6].copy_from_slice(&self.version_major.to_be_bytes());
            buf[6..8].copy_from_slice(&self.version_minor.to_be_bytes());
            buf[8..12].copy_from_slice(&self.thiszone.to_be_bytes());
            buf[12..16].copy_from_slice(&self.sigfigs.to_be_bytes());
            buf[16..20].copy_from_slice(&self.snaplen.to_be_bytes());
            buf[20..24].copy_from_slice(&self.network.to_be_bytes());
        } else {
            buf[0..4].copy_from_slice(&self.magic_number.to_le_bytes());
            buf[4..6].copy_from_slice(&self.version_major.to_le_bytes());
            buf[6..8].copy_from_slice(&self.version_minor.to_le_bytes());
            buf[8..12].copy_from_slice(&self.thiszone.to_le_bytes());
            buf[12..16].copy_from_slice(&self.sigfigs.to_le_bytes());
            buf[16..20].copy_from_slice(&self.snaplen.to_le_bytes());
            buf[20..24].copy_from_slice(&self.network.to_le_bytes());
        }
        buf
    }
}

// ── PcapWriter ───────────────────────────────────────────────────────────────

/// Writes a single legacy PCAP output file.
pub struct PcapWriter {
    inner: BufWriter<File>,
    header: GlobalHeader,
    path: PathBuf,
    packets: u64,
}

impl PcapWriter {
    /// Create and open a new PCAP file at `path`, writing the global header.
    ///
    /// # Errors
    /// Returns [`SortError::Io`] if the file cannot be created.
    pub fn create(path: &Path, header: GlobalHeader) -> Result<Self, SortError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);
        writer.write_all(&header.to_bytes())?;
        Ok(Self {
            inner: writer,
            header,
            path: path.to_owned(),
            packets: 0,
        })
    }

    /// Write one packet record.
    ///
    /// `timestamp_ns` is split into seconds and fractional units that match
    /// the source file's timestamp precision (usec or nsec).
    ///
    /// # Errors
    /// Returns [`SortError::Io`] on write failure.
    pub fn write_packet(
        &mut self,
        timestamp_ns: u64,
        caplen: u32,
        origlen: u32,
        data: &[u8],
    ) -> Result<(), SortError> {
        let (ts_sec, ts_frac) = if self.header.is_nanosecond() {
            (
                (timestamp_ns / 1_000_000_000) as u32,
                (timestamp_ns % 1_000_000_000) as u32,
            )
        } else {
            (
                (timestamp_ns / 1_000_000_000) as u32,
                ((timestamp_ns % 1_000_000_000) / 1_000) as u32,
            )
        };

        let mut rec = [0u8; 16];
        if self.header.is_big_endian() {
            rec[0..4].copy_from_slice(&ts_sec.to_be_bytes());
            rec[4..8].copy_from_slice(&ts_frac.to_be_bytes());
            rec[8..12].copy_from_slice(&caplen.to_be_bytes());
            rec[12..16].copy_from_slice(&origlen.to_be_bytes());
        } else {
            rec[0..4].copy_from_slice(&ts_sec.to_le_bytes());
            rec[4..8].copy_from_slice(&ts_frac.to_le_bytes());
            rec[8..12].copy_from_slice(&caplen.to_le_bytes());
            rec[12..16].copy_from_slice(&origlen.to_le_bytes());
        }

        self.inner.write_all(&rec)?;
        self.inner.write_all(data)?;
        self.packets += 1;
        Ok(())
    }

    /// Flush and close, returning the path and packet count.
    pub fn finish(mut self) -> Result<(PathBuf, u64), SortError> {
        self.inner.flush()?;
        Ok((self.path, self.packets))
    }
}

// ── SlicedWriter ─────────────────────────────────────────────────────────────

/// Manages one or more [`PcapWriter`] instances, opening a new file whenever a
/// packet's timestamp crosses a time-slice boundary.
///
/// When `slice_secs` is `None`, all packets go to a single output file.
pub struct SlicedWriter {
    header: GlobalHeader,
    output_base: PathBuf,
    slice_secs: Option<u64>,
    current: Option<PcapWriter>,
    current_slice_start_ns: u64,
    pub files: Vec<PathBuf>,
    pub total_packets: u64,
}

impl SlicedWriter {
    /// Create a new `SlicedWriter`.
    ///
    /// - `output_base`: path to the output file (no slicing) or directory (slicing).
    /// - `slice_secs`: slice interval in seconds; `None` writes a single file.
    pub fn new(output_base: PathBuf, header: GlobalHeader, slice_secs: Option<u64>) -> Self {
        Self {
            header,
            output_base,
            slice_secs,
            current: None,
            current_slice_start_ns: 0,
            files: Vec::new(),
            total_packets: 0,
        }
    }

    /// Write one packet, opening a new slice file if necessary.
    ///
    /// # Errors
    /// Returns [`SortError::Io`] on write or file-creation failure.
    pub fn write_packet(
        &mut self,
        timestamp_ns: u64,
        caplen: u32,
        origlen: u32,
        data: &[u8],
    ) -> Result<(), SortError> {
        let need_new = match self.slice_secs {
            None => self.current.is_none(),
            Some(secs) => {
                let slice_ns = secs * 1_000_000_000;
                self.current.is_none() || timestamp_ns >= self.current_slice_start_ns + slice_ns
            }
        };

        if need_new {
            self.rotate(timestamp_ns)?;
        }

        self.current
            .as_mut()
            .unwrap()
            .write_packet(timestamp_ns, caplen, origlen, data)?;
        self.total_packets += 1;
        Ok(())
    }

    /// Flush and close all open output files.
    ///
    /// Returns `(files_written, total_packets)`.
    ///
    /// # Errors
    /// Returns [`SortError::Io`] on flush failure.
    pub fn finish(mut self) -> Result<(Vec<PathBuf>, u64), SortError> {
        if let Some(w) = self.current.take() {
            let (path, _) = w.finish()?;
            self.files.push(path);
        }
        Ok((self.files, self.total_packets))
    }

    // ── private ──────────────────────────────────────────────────────────────

    fn rotate(&mut self, timestamp_ns: u64) -> Result<(), SortError> {
        // Close the previous writer.
        if let Some(w) = self.current.take() {
            let (path, _) = w.finish()?;
            self.files.push(path);
        }

        let path = self.output_path(timestamp_ns);
        self.current = Some(PcapWriter::create(&path, self.header)?);

        // Snap the slice boundary to the floor of the slice interval.
        self.current_slice_start_ns = match self.slice_secs {
            None => timestamp_ns,
            Some(secs) => {
                let slice_ns = secs * 1_000_000_000;
                (timestamp_ns / slice_ns) * slice_ns
            }
        };
        Ok(())
    }

    fn output_path(&self, timestamp_ns: u64) -> PathBuf {
        if self.slice_secs.is_none() {
            return self.output_base.clone();
        }
        // Sliced mode: output is a directory, filename encodes the slice start.
        let dt = ns_to_datetime(timestamp_ns);
        let name = dt.format("part_%Y%m%dT%H%M%SZ.pcap").to_string();
        self.output_base.join(name)
    }
}

fn ns_to_datetime(ns: u64) -> DateTime<Utc> {
    let secs = (ns / 1_000_000_000) as i64;
    let nanos = (ns % 1_000_000_000) as u32;
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> GlobalHeader {
        GlobalHeader {
            magic_number: 0xa1b2_c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: 1,
        }
    }

    #[test]
    fn test_global_header_roundtrip_le() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 24);
        // Magic in LE
        assert_eq!(&bytes[0..4], &0xa1b2_c3d4u32.to_le_bytes());
        // snaplen = 65535
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 65535);
    }

    #[test]
    fn test_global_header_big_endian() {
        let hdr = GlobalHeader {
            magic_number: 0xd4c3_b2a1,
            ..make_header()
        };
        assert!(hdr.is_big_endian());
        let bytes = hdr.to_bytes();
        assert_eq!(&bytes[0..4], &0xd4c3_b2a1u32.to_be_bytes());
    }

    #[test]
    fn test_pcap_writer_produces_valid_file() {
        let path = std::env::temp_dir().join("pcap_toolkit_writer_test.pcap");
        let hdr = make_header();
        let mut w = PcapWriter::create(&path, hdr).unwrap();
        let data = vec![0xAAu8; 60];
        w.write_packet(1_700_000_000_000_000_000, 60, 60, &data)
            .unwrap();
        let (_, count) = w.finish().unwrap();
        assert_eq!(count, 1);

        // Verify the file starts with the expected magic.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[0..4], &0xa1b2_c3d4u32.to_le_bytes());
        // File size: 24 (global header) + 16 (record header) + 60 (data) = 100
        assert_eq!(bytes.len(), 100);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_sliced_writer_single_file() {
        let path = std::env::temp_dir().join("pcap_toolkit_sliced_single.pcap");
        let mut sw = SlicedWriter::new(path.clone(), make_header(), None);
        let data = vec![0u8; 40];
        sw.write_packet(1_000_000_000_000, 40, 40, &data).unwrap();
        sw.write_packet(2_000_000_000_000, 40, 40, &data).unwrap();
        let (files, total) = sw.finish().unwrap();
        assert_eq!(total, 2);
        assert_eq!(files.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_sliced_writer_splits_by_hour() {
        let dir = std::env::temp_dir().join("pcap_toolkit_sliced_hour");
        std::fs::create_dir_all(&dir).unwrap();

        let mut sw = SlicedWriter::new(dir.clone(), make_header(), Some(3600));
        let data = vec![0u8; 40];
        // Packet at T=0s (1970-01-01T00:00:00Z)
        sw.write_packet(0, 40, 40, &data).unwrap();
        // Packet at T=3601s → new hour slice
        sw.write_packet(3_601 * 1_000_000_000, 40, 40, &data)
            .unwrap();
        let (files, total) = sw.finish().unwrap();

        assert_eq!(total, 2);
        assert_eq!(files.len(), 2);

        for f in &files {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_dir(&dir);
    }
}
