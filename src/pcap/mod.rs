//! Streaming PCAP / PCAPng reader.
//!
//! Yields one [`PacketInfo`] per packet in file order, without buffering
//! payloads. Uses `pcap-parser` for file framing and `etherparse` for
//! zero-copy layer parsing.

use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::Path;

use etherparse::SlicedPacket;
use pcap_parser::traits::PcapReaderIterator;
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
    ToolkitPcapError::Parse(format!("{e:?}"))
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
                                    let flow_key = parse_flow_key(epb.data);
                                    Some(Ok(PacketInfo {
                                        timestamp_ns: ts_ns,
                                        captured_len: epb.caplen,
                                        original_len: epb.origlen,
                                        flow_key,
                                    }))
                                }
                                Block::SimplePacket(spb) => {
                                    let flow_key = parse_flow_key(spb.data);
                                    Some(Ok(PacketInfo {
                                        timestamp_ns: 0,
                                        captured_len: spb.data.len() as u32,
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

/// Open a file, auto-detect PCAP vs PCAPng, and return a boxed packet iterator.
///
/// Detection is based on the first 4 bytes (magic number).
pub fn open(
    path: &Path,
) -> Result<Box<dyn Iterator<Item = Result<PacketInfo, ToolkitPcapError>>>, ToolkitPcapError> {
    let file = std::fs::File::open(path)?;
    let mut buf = BufReader::new(file);

    // Peek at the magic number (4 bytes).
    let mut magic = [0u8; 4];
    buf.read_exact(&mut magic)?;

    // Re-open so the reader sees the full file including the magic.
    let file2 = std::fs::File::open(path)?;

    let u32_magic = u32::from_le_bytes(magic);
    match u32_magic {
        // Legacy PCAP: native or swapped byte order, usec or nsec precision.
        0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1 => Ok(Box::new(iter_legacy(file2)?)),
        // PCAPng: SHB byte order magic (LE).
        0x0a0d_0d0a => Ok(Box::new(iter_pcapng(file2)?)),
        _ => Err(ToolkitPcapError::Parse(format!(
            "unrecognised file magic: {u32_magic:#010x}"
        ))),
    }
}

/// Open a file and return an iterator that yields both [`PacketInfo`] and the
/// raw captured bytes for each packet.
///
/// Useful for the export pipeline where the payload must be written out.
/// Format auto-detection works the same as [`open`].
pub fn open_with_payload(
    path: &Path,
) -> Result<Box<dyn Iterator<Item = Result<PacketData, ToolkitPcapError>>>, ToolkitPcapError> {
    let file = std::fs::File::open(path)?;
    let mut buf = BufReader::new(file);

    let mut magic = [0u8; 4];
    buf.read_exact(&mut magic)?;

    let file2 = std::fs::File::open(path)?;

    let u32_magic = u32::from_le_bytes(magic);
    match u32_magic {
        0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1 => {
            Ok(Box::new(iter_legacy_with_payload(file2)?))
        }
        0x0a0d_0d0a => Ok(Box::new(iter_pcapng_with_payload(file2)?)),
        _ => Err(ToolkitPcapError::Parse(format!(
            "unrecognised file magic: {u32_magic:#010x}"
        ))),
    }
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
                                    let data = epb.data.to_vec();
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
                                    let data = spb.data.to_vec();
                                    let flow_key = parse_flow_key(&data);
                                    Some(Ok(PacketData {
                                        info: PacketInfo {
                                            timestamp_ns: 0,
                                            captured_len: spb.data.len() as u32,
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
