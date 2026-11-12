//! Streaming PCAP / PCAPng reader.
//!
//! Yields one [`PacketInfo`] per packet in file order, without buffering
//! payloads. Uses `pcap-parser` for file framing and `etherparse` for
//! zero-copy layer parsing.

mod source;

use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

pub use source::{PacketSource, STDIN_ARG};

use etherparse::SlicedPacket;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError, PcapNGReader};

use crate::error::PcapError as ToolkitPcapError;
use crate::flow::FlowKey;

/// Parsed metadata for a single packet, together with the raw captured bytes.
#[derive(Debug)]
pub struct PacketData {
    /// Parsed metadata (same as [`PacketInfo`]).
    pub info: PacketInfo,
    /// Raw bytes as captured (Ethernet frame or link-layer PDU).
    pub data: Vec<u8>,
}

/// Parsed metadata for a single packet.
#[derive(Debug)]
pub struct PacketInfo {
    /// Timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Number of bytes captured (on-wire may be larger if truncated by snap length).
    pub captured_len: u32,
    /// On-wire packet length.
    pub original_len: u32,
    /// Parsed 5-tuple, if the packet contains an IP layer with a transport header.
    pub flow_key: Option<FlowKey>,
}

/// Read buffer size passed to `pcap-parser` (64 KiB).
const BUF_SIZE: usize = 65536;

/// Convert a pcap-parser error (with any slice type) to our error type.
fn map_pcap_err<I: std::fmt::Debug>(e: PcapError<I>) -> ToolkitPcapError {
    ToolkitPcapError::Parse(e.to_string())
}

/// Iterate over packets in a legacy PCAP file.
///
/// Automatically detects nanosecond-precision magic and adjusts timestamps.
pub fn iter_legacy<R: Read>(
    reader: R,
) -> Result<impl Iterator<Item = Result<PacketInfo, ToolkitPcapError>>, ToolkitPcapError> {
    let mut pcap = LegacyPcapReader::new(BUF_SIZE, reader).map_err(map_pcap_err)?;
    let mut ns_precision = false;

    // Read the global header to detect ns-resolution magic.
    loop {
        match pcap.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::LegacyHeader(hdr) = block {
                    // Magic 0xa1b23c4d = nanosecond resolution.
                    ns_precision = hdr.magic_number == 0xa1b2_3c4d;
                    pcap.consume(offset);
                    break;
                }
                pcap.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap.refill().map_err(map_pcap_err)?;
            }
            Err(e) => return Err(map_pcap_err(e)),
        }
    }

    Ok(LegacyIter {
        reader: pcap,
        ns_precision,
        done: false,
    })
}

struct LegacyIter<R: Read> {
    reader: LegacyPcapReader<R>,
    ns_precision: bool,
    done: bool,
}

impl<R: Read> Iterator for LegacyIter<R> {
    type Item = Result<PacketInfo, ToolkitPcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    let result = if let PcapBlockOwned::Legacy(pkt) = block {
                        let ts_ns = if self.ns_precision {
                            u64::from(pkt.ts_sec) * 1_000_000_000 + u64::from(pkt.ts_usec)
                        } else {
                            u64::from(pkt.ts_sec) * 1_000_000_000 + u64::from(pkt.ts_usec) * 1_000
                        };
                        let flow_key = parse_flow_key(pkt.data);
                        Some(Ok(PacketInfo {
                            timestamp_ns: ts_ns,
                            captured_len: pkt.caplen,
                            original_len: pkt.origlen,
                            flow_key,
                        }))
                    } else {
                        None
                    };
                    self.reader.consume(offset);
                    if let Some(item) = result {
                        return Some(item);
                    }
                }
                Err(PcapError::Eof) => {
                    self.done = true;
                    return None;
                }
                Err(PcapError::Incomplete(_)) => {
                    if let Err(e) = self.reader.refill() {
                        self.done = true;
                        return Some(Err(map_pcap_err(e)));
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(map_pcap_err(e)));
                }
            }
        }
    }
}

/// Iterate over packets in a PCAPng file.
///
/// Uses default timestamp resolution (microseconds) and zero offset.
/// Full IDB-aware timestamp decoding is deferred to a later phase.
pub fn iter_pcapng<R: Read>(
    reader: R,
) -> Result<impl Iterator<Item = Result<PacketInfo, ToolkitPcapError>>, ToolkitPcapError> {
    let pcap = PcapNGReader::new(BUF_SIZE, reader).map_err(map_pcap_err)?;
    Ok(PcapNGIter {
        reader: pcap,
        done: false,
    })
}

struct PcapNGIter<R: Read> {
    reader: PcapNGReader<R>,
    done: bool,
}

impl<R: Read> Iterator for PcapNGIter<R> {
    type Item = Result<PacketInfo, ToolkitPcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    // Default: usec resolution, zero ts_offset.
                    const RESOLUTION: u64 = 1_000_000;
                    const TS_OFFSET: u64 = 0;

                    let result = match block {
                        PcapBlockOwned::NG(ng_block) => {
                            use pcap_parser::Block;
                            match ng_block {
                                Block::EnhancedPacket(epb) => {
                                    let (ts_sec, ts_frac) = epb.decode_ts(TS_OFFSET, RESOLUTION);
                                    let ts_ns = u64::from(ts_sec) * 1_000_000_000
                                        + u64::from(ts_frac) * (1_000_000_000 / RESOLUTION);
                                    let flow_key = parse_flow_key(epb.packet_data());
                                    Some(Ok(PacketInfo {
                                        timestamp_ns: ts_ns,
                                        captured_len: epb.caplen,
                                        original_len: epb.origlen,
                                        flow_key,
                                    }))
                                }
                                Block::SimplePacket(spb) => {
                                    let flow_key = parse_flow_key(spb.packet_data());
                                    Some(Ok(PacketInfo {
                                        timestamp_ns: 0,
                                        captured_len: spb.packet_data().len() as u32,
                                        original_len: spb.origlen,
                                        flow_key,
                                    }))
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    self.reader.consume(offset);
                    if let Some(item) = result {
                        return Some(item);
                    }
                }
                Err(PcapError::Eof) => {
                    self.done = true;
                    return None;
                }
                Err(PcapError::Incomplete(_)) => {
                    if let Err(e) = self.reader.refill() {
                        self.done = true;
                        return Some(Err(map_pcap_err(e)));
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(map_pcap_err(e)));
                }
            }
        }
    }
}

/// Boxed iterator over packet metadata.
pub type PacketInfoIter = Box<dyn Iterator<Item = Result<PacketInfo, ToolkitPcapError>>>;

/// Boxed iterator over packet metadata plus raw bytes.
pub type PacketDataIter = Box<dyn Iterator<Item = Result<PacketData, ToolkitPcapError>>>;

/// Capture container detected from the leading magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureFormat {
    Legacy,
    PcapNg,
}

/// Size of the legacy PCAP global header.
const LEGACY_HEADER_LEN: usize = 24;

/// Smallest valid PCAPng Section Header Block.
const MIN_SHB_LEN: usize = 28;

/// A reader that first replays an already-consumed `prefix`, then continues
/// with `inner`.
///
/// Unlike [`std::io::Chain`], the whole prefix is returned by the **first**
/// `read()` call (as long as the caller's buffer is large enough). That
/// matters because `pcap-parser`'s reader constructors parse the file header
/// out of a single `read()` and fail with `Incomplete` otherwise.
struct Prefixed<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R: Read> Read for Prefixed<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let pending = &self.prefix[self.pos..];
        if pending.is_empty() {
            return self.inner.read(buf);
        }
        let count = pending.len().min(buf.len());
        buf[..count].copy_from_slice(&pending[..count]);
        self.pos += count;
        Ok(count)
    }
}

/// Classify the container from its magic number and consume its complete
/// file header (legacy global header, or the whole PCAPng SHB), then return
/// a reader that yields the full stream again from byte 0.
///
/// Works on non-seekable streams (pipes, stdin): nothing is re-opened or
/// seeked, and `read_exact` tolerates short reads while collecting the header.
fn sniff<R: Read>(mut reader: R) -> Result<(CaptureFormat, Prefixed<R>), ToolkitPcapError> {
    let mut head = vec![0u8; 4];
    read_header(&mut reader, &mut head)?;

    let format = match u32::from_le_bytes([head[0], head[1], head[2], head[3]]) {
        // Legacy PCAP: native or swapped byte order, usec or nsec precision.
        0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1 => CaptureFormat::Legacy,
        // PCAPng: SHB block type (palindromic, byte-order independent).
        0x0a0d_0d0a => CaptureFormat::PcapNg,
        other => {
            return Err(ToolkitPcapError::Parse(format!(
                "unrecognised file magic: {other:#010x}"
            )));
        }
    };

    let header_len = match format {
        CaptureFormat::Legacy => LEGACY_HEADER_LEN,
        CaptureFormat::PcapNg => {
            // block total length (4..8) + byte-order magic (8..12).
            head.resize(12, 0);
            read_header(&mut reader, &mut head[4..12])?;
            shb_len(&head)?
        }
    };
    let already = head.len();
    head.resize(header_len, 0);
    read_header(&mut reader, &mut head[already..])?;

    Ok((
        format,
        Prefixed {
            prefix: head,
            pos: 0,
            inner: reader,
        },
    ))
}

/// `read_exact` for the file header, turning a premature end of stream into a
/// descriptive parse error (an empty pipe otherwise surfaces as the cryptic
/// "failed to fill whole buffer"). Other I/O errors are passed through.
fn read_header<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), ToolkitPcapError> {
    reader.read_exact(buf).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            ToolkitPcapError::Parse(
                "input is empty or truncated: no complete PCAP/PCAPng file header".to_owned(),
            )
        } else {
            ToolkitPcapError::Io(err)
        }
    })
}

/// Total length of a PCAPng SHB from its first 12 bytes, validated against
/// the read buffer so the parser can see it in one piece.
fn shb_len(head: &[u8]) -> Result<usize, ToolkitPcapError> {
    let len_bytes = [head[4], head[5], head[6], head[7]];
    let len = match [head[8], head[9], head[10], head[11]] {
        [0x4d, 0x3c, 0x2b, 0x1a] => u32::from_le_bytes(len_bytes),
        [0x1a, 0x2b, 0x3c, 0x4d] => u32::from_be_bytes(len_bytes),
        bom => {
            return Err(ToolkitPcapError::Parse(format!(
                "invalid PCAPng byte-order magic: {bom:02x?}"
            )));
        }
    } as usize;
    if !(MIN_SHB_LEN..=BUF_SIZE).contains(&len) || len % 4 != 0 {
        return Err(ToolkitPcapError::Parse(format!(
            "invalid PCAPng section header length: {len}"
        )));
    }
    Ok(len)
}

/// Auto-detect PCAP vs PCAPng on any byte stream and return a packet iterator.
///
/// This is the generic entry point: `R` may be a file, a pipe, stdin, or an
/// in-memory `Cursor`. Detection is based on the first 4 bytes (magic number).
///
/// # Errors
/// [`ToolkitPcapError::Io`] if fewer than 4 bytes can be read;
/// [`ToolkitPcapError::Parse`] for an unknown magic or a malformed header.
pub fn open_reader<R: Read + 'static>(reader: R) -> Result<PacketInfoIter, ToolkitPcapError> {
    match sniff(reader)? {
        (CaptureFormat::Legacy, stream) => Ok(Box::new(iter_legacy(stream)?)),
        (CaptureFormat::PcapNg, stream) => Ok(Box::new(iter_pcapng(stream)?)),
    }
}

/// Like [`open_reader`], but each item also carries the raw captured bytes.
///
/// # Errors
/// Same as [`open_reader`].
pub fn open_reader_with_payload<R: Read + 'static>(
    reader: R,
) -> Result<PacketDataIter, ToolkitPcapError> {
    match sniff(reader)? {
        (CaptureFormat::Legacy, stream) => Ok(Box::new(iter_legacy_with_payload(stream)?)),
        (CaptureFormat::PcapNg, stream) => Ok(Box::new(iter_pcapng_with_payload(stream)?)),
    }
}

/// Open a [`PacketSource`] (file or stdin) and return a packet iterator.
///
/// # Errors
/// Same as [`open_reader`], plus I/O errors from opening the file.
pub fn open_source(source: &PacketSource) -> Result<PacketInfoIter, ToolkitPcapError> {
    match source {
        PacketSource::File(path) => open_reader(File::open(path)?),
        PacketSource::Stdin => open_reader(std::io::stdin()),
    }
}

/// Open a [`PacketSource`] (file or stdin) and return an iterator that also
/// yields the raw captured bytes.
///
/// # Errors
/// Same as [`open_source`].
pub fn open_source_with_payload(source: &PacketSource) -> Result<PacketDataIter, ToolkitPcapError> {
    match source {
        PacketSource::File(path) => open_reader_with_payload(File::open(path)?),
        PacketSource::Stdin => open_reader_with_payload(std::io::stdin()),
    }
}

/// Open a file, auto-detect PCAP vs PCAPng, and return a boxed packet iterator.
///
/// Detection is based on the first 4 bytes (magic number).
pub fn open(path: &Path) -> Result<PacketInfoIter, ToolkitPcapError> {
    open_reader(File::open(path)?)
}

/// Open a file and return an iterator that yields both [`PacketInfo`] and the
/// raw captured bytes for each packet.
///
/// Useful for the export pipeline where the payload must be written out.
/// Format auto-detection works the same as [`open`].
pub fn open_with_payload(path: &Path) -> Result<PacketDataIter, ToolkitPcapError> {
    open_reader_with_payload(File::open(path)?)
}

fn iter_legacy_with_payload<R: Read + 'static>(
    reader: R,
) -> Result<impl Iterator<Item = Result<PacketData, ToolkitPcapError>>, ToolkitPcapError> {
    let mut pcap = LegacyPcapReader::new(BUF_SIZE, reader).map_err(map_pcap_err)?;
    let mut ns_precision = false;

    loop {
        match pcap.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::LegacyHeader(hdr) = block {
                    ns_precision = hdr.magic_number == 0xa1b2_3c4d;
                    pcap.consume(offset);
                    break;
                }
                pcap.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap.refill().map_err(map_pcap_err)?;
            }
            Err(e) => return Err(map_pcap_err(e)),
        }
    }

    Ok(LegacyWithPayloadIter {
        reader: pcap,
        ns_precision,
        done: false,
    })
}

struct LegacyWithPayloadIter<R: Read> {
    reader: LegacyPcapReader<R>,
    ns_precision: bool,
    done: bool,
}

impl<R: Read> Iterator for LegacyWithPayloadIter<R> {
    type Item = Result<PacketData, ToolkitPcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    let result = if let PcapBlockOwned::Legacy(pkt) = block {
                        let ts_ns = if self.ns_precision {
                            u64::from(pkt.ts_sec) * 1_000_000_000 + u64::from(pkt.ts_usec)
                        } else {
                            u64::from(pkt.ts_sec) * 1_000_000_000 + u64::from(pkt.ts_usec) * 1_000
                        };
                        let data = pkt.data.to_vec();
                        let flow_key = parse_flow_key(&data);
                        Some(Ok(PacketData {
                            info: PacketInfo {
                                timestamp_ns: ts_ns,
                                captured_len: pkt.caplen,
                                original_len: pkt.origlen,
                                flow_key,
                            },
                            data,
                        }))
                    } else {
                        None
                    };
                    self.reader.consume(offset);
                    if let Some(item) = result {
                        return Some(item);
                    }
                }
                Err(PcapError::Eof) => {
                    self.done = true;
                    return None;
                }
                Err(PcapError::Incomplete(_)) => {
                    if let Err(e) = self.reader.refill() {
                        self.done = true;
                        return Some(Err(map_pcap_err(e)));
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(map_pcap_err(e)));
                }
            }
        }
    }
}

fn iter_pcapng_with_payload<R: Read + 'static>(
    reader: R,
) -> Result<impl Iterator<Item = Result<PacketData, ToolkitPcapError>>, ToolkitPcapError> {
    let pcap = PcapNGReader::new(BUF_SIZE, reader).map_err(map_pcap_err)?;
    Ok(PcapNGWithPayloadIter {
        reader: pcap,
        done: false,
    })
}

struct PcapNGWithPayloadIter<R: Read> {
    reader: PcapNGReader<R>,
    done: bool,
}

impl<R: Read> Iterator for PcapNGWithPayloadIter<R> {
    type Item = Result<PacketData, ToolkitPcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    const RESOLUTION: u64 = 1_000_000;
                    const TS_OFFSET: u64 = 0;

                    let result = match block {
                        PcapBlockOwned::NG(ng_block) => {
                            use pcap_parser::Block;
                            match ng_block {
                                Block::EnhancedPacket(epb) => {
                                    let (ts_sec, ts_frac) = epb.decode_ts(TS_OFFSET, RESOLUTION);
                                    let ts_ns = u64::from(ts_sec) * 1_000_000_000
                                        + u64::from(ts_frac) * (1_000_000_000 / RESOLUTION);
                                    let data = epb.packet_data().to_vec();
                                    let flow_key = parse_flow_key(&data);
                                    Some(Ok(PacketData {
                                        info: PacketInfo {
                                            timestamp_ns: ts_ns,
                                            captured_len: epb.caplen,
                                            original_len: epb.origlen,
                                            flow_key,
                                        },
                                        data,
                                    }))
                                }
                                Block::SimplePacket(spb) => {
                                    let data = spb.packet_data().to_vec();
                                    let flow_key = parse_flow_key(&data);
                                    Some(Ok(PacketData {
                                        info: PacketInfo {
                                            timestamp_ns: 0,
                                            captured_len: spb.packet_data().len() as u32,
                                            original_len: spb.origlen,
                                            flow_key,
                                        },
                                        data,
                                    }))
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    self.reader.consume(offset);
                    if let Some(item) = result {
                        return Some(item);
                    }
                }
                Err(PcapError::Eof) => {
                    self.done = true;
                    return None;
                }
                Err(PcapError::Incomplete(_)) => {
                    if let Err(e) = self.reader.refill() {
                        self.done = true;
                        return Some(Err(map_pcap_err(e)));
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(map_pcap_err(e)));
                }
            }
        }
    }
}

/// Count packets per flow ID in a single streaming pass over `path`.
///
/// Applies `filter` and `bpf` to each packet (caller must clear
/// `filter.flow_ids` to avoid circular exclusion). Non-IP packets
/// (no flow key) are not counted.
///
/// Returns a map from flow ID → packet count.
///
/// # Errors
/// Returns [`ToolkitPcapError`] on I/O or parse failure.
pub fn count_flows_in_file(
    path: &Path,
    filter: &crate::filter::Filter,
    bpf: Option<&crate::bpf::BpfExpr>,
    unidirectional: bool,
) -> Result<std::collections::HashMap<u64, u64>, ToolkitPcapError> {
    use crate::filter::PacketMeta;
    use std::collections::HashMap;

    let mut counts: HashMap<u64, u64> = HashMap::new();
    let has_filter = !filter.is_empty() || bpf.is_some();

    for item in open_with_payload(path)? {
        let packet = item?;
        let meta = PacketMeta::from_packet(
            packet.info.timestamp_ns,
            packet.info.captured_len,
            &packet.data,
        );

        if has_filter {
            let ok =
                (filter.is_empty() || filter.matches(&meta)) && bpf.is_none_or(|b| b.eval(&meta));
            if !ok {
                continue;
            }
        }

        if let Some(ref key) = meta.flow_key {
            let id = key.flow_id(unidirectional);
            *counts.entry(id).or_default() += 1;
        }
    }

    Ok(counts)
}

/// Attempt to extract the 5-tuple from an Ethernet frame's payload.
///
/// Returns `None` for non-IP or unsupported protocols.
fn parse_flow_key(data: &[u8]) -> Option<FlowKey> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    let (src_ip, dst_ip, protocol) = match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(v4)) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                h.protocol().0,
            )
        }
        Some(etherparse::NetSlice::Ipv6(v6)) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                h.next_header().0,
            )
        }
        // ARP, unknown, or missing network layer — not a flow.
        _ => return None,
    };

    let (src_port, dst_port) = match &sliced.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port()),
        Some(etherparse::TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port()),
        _ => (0, 0),
    };

    Some(FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    /// Minimal Ethernet/IPv4/UDP frame (checksums irrelevant for parsing).
    fn udp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 28, 0, 0, 0, 0, 64, 17, 0, 0, // ver/ihl .. proto=UDP, csum
            10, 0, 0, 1, // src
            10, 0, 0, 2, // dst
        ]);
        frame.extend_from_slice(&[0x13, 0x88, 0x00, 0x35, 0x00, 0x08, 0, 0]); // 5000 → 53
        frame
    }

    /// Hand-built little-endian PCAPng: SHB + IDB (Ethernet) + one EPB.
    fn pcapng_bytes(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // SHB (28 bytes)
        for word in [0x0A0D_0D0Au32, 28, 0x1A2B_3C4D] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&1u16.to_le_bytes()); // major
        out.extend_from_slice(&0u16.to_le_bytes()); // minor
        out.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown
        out.extend_from_slice(&28u32.to_le_bytes());
        // IDB (20 bytes)
        for word in [1u32, 20] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&1u16.to_le_bytes()); // LINKTYPE_ETHERNET
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());
        // EPB
        let padded = payload.len().div_ceil(4) * 4;
        let total = (32 + padded) as u32;
        let caplen = payload.len() as u32;
        for word in [6u32, total, 0, 0, 1_000_000, caplen, caplen] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(payload);
        out.resize(out.len() + (padded - payload.len()), 0);
        out.extend_from_slice(&total.to_le_bytes());
        out
    }

    fn count_ok<T>(iter: impl Iterator<Item = Result<T, ToolkitPcapError>>) -> usize {
        iter.inspect(|item| {
            if let Err(err) = item {
                panic!("packet error: {err}");
            }
        })
        .count()
    }

    #[test]
    fn test_open_reader_matches_open_for_legacy_fixture() {
        let path = fixture("mixed.pcap");
        let bytes = std::fs::read(&path).unwrap();

        let from_file: Vec<(u64, u32)> = open(&path)
            .unwrap()
            .map(|pkt| {
                pkt.map(|info| (info.timestamp_ns, info.captured_len))
                    .unwrap()
            })
            .collect();
        let from_memory: Vec<(u64, u32)> = open_reader(Cursor::new(bytes))
            .unwrap()
            .map(|pkt| {
                pkt.map(|info| (info.timestamp_ns, info.captured_len))
                    .unwrap()
            })
            .collect();

        assert!(!from_file.is_empty());
        assert_eq!(from_file, from_memory);
    }

    #[test]
    fn test_open_reader_with_payload_returns_bytes() {
        let path = fixture("dns_exchange.pcap");
        let bytes = std::fs::read(&path).unwrap();
        let expected = count_ok(open_with_payload(&path).unwrap());

        let packets: Vec<PacketData> = open_reader_with_payload(Cursor::new(bytes))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(packets.len(), expected);
        for pkt in &packets {
            assert_eq!(pkt.data.len(), pkt.info.captured_len as usize);
        }
    }

    #[test]
    fn test_open_reader_pcapng_in_memory() {
        let frame = udp_frame();
        let bytes = pcapng_bytes(&frame);

        let infos: Vec<PacketInfo> = open_reader(Cursor::new(bytes.clone()))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].captured_len as usize, frame.len());
        let key = infos[0].flow_key.as_ref().expect("UDP flow key");
        assert_eq!((key.protocol, key.dst_port), (17, 53));

        let datas: Vec<PacketData> = open_reader_with_payload(Cursor::new(bytes))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(datas.len(), 1);
        assert_eq!(datas[0].data, frame);
    }

    /// A reader that hands out at most one byte per `read()` — the worst case
    /// a pipe can legally produce.
    struct Trickle(Cursor<Vec<u8>>);

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let limit = buf.len().min(1);
            self.0.read(&mut buf[..limit])
        }
    }

    #[test]
    fn test_sniff_replays_whole_stream_and_header_in_first_read() {
        let bytes = pcapng_bytes(&udp_frame());
        let (format, mut stream) = sniff(Trickle(Cursor::new(bytes.clone()))).unwrap();
        assert_eq!(format, CaptureFormat::PcapNg);

        // First read must deliver the complete SHB even though the inner
        // reader trickles one byte at a time.
        let mut first = vec![0u8; BUF_SIZE];
        let got = stream.read(&mut first).unwrap();
        assert_eq!(got, MIN_SHB_LEN);

        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        first.truncate(got);
        first.extend_from_slice(&rest);
        assert_eq!(first, bytes);
    }

    #[test]
    fn test_prefixed_splits_prefix_across_small_buffers() {
        let mut stream = Prefixed {
            prefix: vec![1, 2, 3],
            pos: 0,
            inner: Cursor::new(vec![4, 5]),
        };
        let mut buf = [0u8; 2];
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [1, 2]);
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 3);
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [4, 5]);
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn test_open_reader_survives_one_byte_reads() {
        // Simulates a slow pipe (e.g. `tcpdump -w - | pcap-toolkit stats -`).
        let legacy = std::fs::read(fixture("mixed.pcap")).unwrap();
        let expected = count_ok(open_reader(Cursor::new(legacy.clone())).unwrap());
        assert_eq!(
            count_ok(open_reader(Trickle(Cursor::new(legacy))).unwrap()),
            expected
        );

        let pcapng = pcapng_bytes(&udp_frame());
        assert_eq!(
            count_ok(open_reader_with_payload(Trickle(Cursor::new(pcapng))).unwrap()),
            1
        );
    }

    #[test]
    fn test_sniff_detects_all_legacy_magics() {
        for magic in [0xa1b2_c3d4u32, 0xd4c3_b2a1, 0xa1b2_3c4d, 0x4d3c_b2a1] {
            let mut header = magic.to_le_bytes().to_vec();
            header.resize(LEGACY_HEADER_LEN, 0);
            let (format, _) = sniff(Cursor::new(header)).unwrap();
            assert_eq!(format, CaptureFormat::Legacy, "magic {magic:#010x}");
        }
    }

    fn is_truncation_error(err: Option<ToolkitPcapError>) -> bool {
        matches!(err, Some(ToolkitPcapError::Parse(msg)) if msg.contains("empty or truncated"))
    }

    #[test]
    fn test_sniff_truncated_headers_are_reported() {
        let legacy_short = vec![0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0];
        let pcapng_tiny = pcapng_bytes(&[])[..8].to_vec(); // stops inside length/BOM
        let pcapng_short = pcapng_bytes(&[])[..20].to_vec(); // stops inside SHB body
        for input in [legacy_short, pcapng_tiny, pcapng_short] {
            assert!(is_truncation_error(sniff(Cursor::new(input)).err()));
        }
    }

    #[test]
    fn test_read_header_passes_through_other_io_errors() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk on fire"))
            }
        }
        let err = sniff(Broken).err();
        assert!(matches!(err, Some(ToolkitPcapError::Io(io)) if io.to_string() == "disk on fire"));
    }

    #[test]
    fn test_shb_len_validation() {
        let mut head = pcapng_bytes(&[])[..12].to_vec();
        assert_eq!(shb_len(&head).unwrap(), MIN_SHB_LEN);

        // Big-endian SHB.
        let mut be = vec![0x0A, 0x0D, 0x0D, 0x0A];
        be.extend_from_slice(&32u32.to_be_bytes());
        be.extend_from_slice(&[0x1a, 0x2b, 0x3c, 0x4d]);
        assert_eq!(shb_len(&be).unwrap(), 32);

        // Bad byte-order magic.
        head[8..12].copy_from_slice(&[0, 0, 0, 0]);
        assert!(shb_len(&head).is_err());

        // Too short, unaligned, larger than the parser buffer.
        for bad in [12u32, 30, (BUF_SIZE + 4) as u32] {
            let mut head = pcapng_bytes(&[])[..12].to_vec();
            head[4..8].copy_from_slice(&bad.to_le_bytes());
            let err = shb_len(&head).unwrap_err();
            assert!(err.to_string().contains("section header length"), "{bad}");
        }
    }

    #[test]
    fn test_open_reader_unknown_magic() {
        let err = open_reader(Cursor::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0])).err();
        match err {
            Some(ToolkitPcapError::Parse(msg)) => assert!(msg.contains("0xefbeadde")),
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn test_open_reader_empty_or_short_stream_is_reported() {
        for input in [vec![], vec![0xd4, 0xc3]] {
            assert!(is_truncation_error(
                open_reader_with_payload(Cursor::new(input.clone())).err()
            ));
            assert!(is_truncation_error(open_reader(Cursor::new(input)).err()));
        }
    }

    #[test]
    fn test_open_source_file() {
        let path = fixture("http_session.pcap");
        let expected = count_ok(open(&path).unwrap());
        let source = PacketSource::File(path);
        assert_eq!(count_ok(open_source(&source).unwrap()), expected);
        assert_eq!(
            count_ok(open_source_with_payload(&source).unwrap()),
            expected
        );
    }

    #[test]
    fn test_open_source_missing_file_is_io_error() {
        let source = PacketSource::File("/nonexistent/missing.pcap".into());
        assert!(matches!(
            open_source(&source).err(),
            Some(ToolkitPcapError::Io(_))
        ));
        assert!(matches!(
            open_source_with_payload(&source).err(),
            Some(ToolkitPcapError::Io(_))
        ));
    }
}
