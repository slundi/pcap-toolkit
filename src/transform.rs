//! Phase 4: Packet-level transformations applied during the sort second pass.
//!
//! Transformations are applied in this order for each packet:
//! 1. **IP address mapping** — replace IP addresses in-place.
//! 2. **Payload truncation** — shorten the payload and update length fields.
//! 3. **Checksum recalculation** — recompute IPv4 header and TCP/UDP transport
//!    checksums whenever the above steps modified the packet bytes.
//!
//! Timestamp shifting is computed once before the loop and applied per-packet
//! without touching the byte payload.
//!
//! Only Ethernet frames (link type 1) carrying IPv4 or IPv6 are supported.
//! A single 802.1Q VLAN tag is transparently handled. Other link types and
//! encapsulations are passed through untouched.

use std::net::IpAddr;

use thiserror::Error;

// ── EtherType / protocol constants ───────────────────────────────────────────

const ET_IPV4: u16 = 0x0800;
const ET_IPV6: u16 = 0x86DD;
const ET_VLAN: u16 = 0x8100;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

// ── Public types ─────────────────────────────────────────────────────────────

/// Errors produced during transform option parsing.
#[derive(Debug, Error)]
pub enum TransformError {
    #[error("invalid IP mapping '{0}': expected OLD_IP=NEW_IP")]
    InvalidMapping(String),
    #[error("cross-family IP mapping is not supported: '{0}' → '{1}'")]
    CrossFamily(String, String),
}

/// One IP address replacement rule.
#[derive(Debug, Clone)]
pub struct IpMapping {
    /// Address to search for in packet headers.
    pub old: IpAddr,
    /// Address to write in place of `old`.
    pub new: IpAddr,
}

/// All packet-level transformation options for a sort run.
#[derive(Debug, Default, Clone)]
pub struct TransformOptions {
    /// Truncate the payload of each packet to at most this many bytes.
    /// Ethernet, IP, and transport headers are always preserved.
    pub max_payload_bytes: Option<u32>,
    /// When set, all timestamps are shifted so the first sorted packet starts
    /// at exactly this nanosecond epoch value.
    ///
    /// The delta is computed once in [`second_pass`] and passed as `ts_delta`.
    pub timestamp_start_ns: Option<u64>,
    /// IP address replacement rules, evaluated in order for every packet.
    pub ip_map: Vec<IpMapping>,
}

impl TransformOptions {
    /// Returns `true` when no transformations are configured.
    pub fn is_empty(&self) -> bool {
        self.max_payload_bytes.is_none()
            && self.timestamp_start_ns.is_none()
            && self.ip_map.is_empty()
    }
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Parse `"OLD_IP=NEW_IP"` into an [`IpMapping`].
///
/// Both sides must be valid IP addresses of the **same** address family.
/// Cross-family mappings (IPv4↔IPv6) are rejected with [`TransformError::CrossFamily`].
///
/// # Errors
/// [`TransformError::InvalidMapping`] — format wrong or address unparsable.
/// [`TransformError::CrossFamily`] — address families differ.
pub fn parse_ip_mapping(s: &str) -> Result<IpMapping, TransformError> {
    let (old_s, new_s) = s
        .split_once('=')
        .ok_or_else(|| TransformError::InvalidMapping(s.to_owned()))?;

    let old: IpAddr = old_s
        .trim()
        .parse()
        .map_err(|_| TransformError::InvalidMapping(s.to_owned()))?;
    let new: IpAddr = new_s
        .trim()
        .parse()
        .map_err(|_| TransformError::InvalidMapping(s.to_owned()))?;

    match (&old, &new) {
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
            return Err(TransformError::CrossFamily(
                old.to_string(),
                new.to_string(),
            ));
        }
        _ => {}
    }

    Ok(IpMapping { old, new })
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Apply all configured transformations to one captured packet.
///
/// Mutates `data` in place and returns `(new_timestamp_ns, new_caplen, new_origlen)`.
///
/// - `ts_delta` — pre-computed nanosecond shift; `0` disables timestamp shifting.
/// - `origlen` — original wire length from the PCAP record header.
pub fn apply(
    data: &mut Vec<u8>,
    timestamp_ns: u64,
    ts_delta: i64,
    origlen: u32,
    opts: &TransformOptions,
) -> (u64, u32, u32) {
    let new_ts = if ts_delta != 0 {
        (timestamp_ns as i64).saturating_add(ts_delta).max(0) as u64
    } else {
        timestamp_ns
    };

    let ip_changed = !opts.ip_map.is_empty() && apply_ip_map(data, &opts.ip_map);

    let (new_origlen, truncated) = if let Some(max_bytes) = opts.max_payload_bytes {
        do_truncate(data, max_bytes, origlen)
    } else {
        (origlen, false)
    };

    if ip_changed || truncated {
        recalculate_checksums(data);
    }

    let new_caplen = data.len() as u32;
    (new_ts, new_caplen, new_origlen)
}

// ── Frame navigation ──────────────────────────────────────────────────────────

/// Return `(ip_header_offset, ethertype)` for IPv4/IPv6 frames.
///
/// Handles a single 802.1Q VLAN tag. Returns `None` for non-IP frames or
/// frames that are too short to parse.
fn find_ip(data: &[u8]) -> Option<(usize, u16)> {
    if data.len() < 14 {
        return None;
    }
    let et = u16::from_be_bytes([data[12], data[13]]);
    if et == ET_VLAN {
        if data.len() < 18 {
            return None;
        }
        let inner = u16::from_be_bytes([data[16], data[17]]);
        if inner == ET_IPV4 || inner == ET_IPV6 {
            Some((18, inner))
        } else {
            None
        }
    } else if et == ET_IPV4 || et == ET_IPV6 {
        Some((14, et))
    } else {
        None
    }
}

// ── IP address mapping ────────────────────────────────────────────────────────

/// Replace IP addresses in the packet's IP header.
///
/// Returns `true` if at least one address was replaced.
fn apply_ip_map(data: &mut [u8], mappings: &[IpMapping]) -> bool {
    let Some((ip_off, et)) = find_ip(data) else {
        return false;
    };
    let mut changed = false;

    if et == ET_IPV4 {
        if data.len() < ip_off + 20 {
            return false;
        }
        for m in mappings {
            if let (IpAddr::V4(old_v4), IpAddr::V4(new_v4)) = (&m.old, &m.new) {
                let old_b = old_v4.octets();
                let new_b = new_v4.octets();
                // src IP: bytes 12–16 of the IPv4 header.
                if data[ip_off + 12..ip_off + 16] == old_b {
                    data[ip_off + 12..ip_off + 16].copy_from_slice(&new_b);
                    changed = true;
                }
                // dst IP: bytes 16–20 of the IPv4 header.
                if data[ip_off + 16..ip_off + 20] == old_b {
                    data[ip_off + 16..ip_off + 20].copy_from_slice(&new_b);
                    changed = true;
                }
            }
        }
    } else if et == ET_IPV6 {
        if data.len() < ip_off + 40 {
            return false;
        }
        for m in mappings {
            if let (IpAddr::V6(old_v6), IpAddr::V6(new_v6)) = (&m.old, &m.new) {
                let old_b = old_v6.octets();
                let new_b = new_v6.octets();
                // src IP: bytes 8–24 of the IPv6 header.
                if data[ip_off + 8..ip_off + 24] == old_b {
                    data[ip_off + 8..ip_off + 24].copy_from_slice(&new_b);
                    changed = true;
                }
                // dst IP: bytes 24–40 of the IPv6 header.
                if data[ip_off + 24..ip_off + 40] == old_b {
                    data[ip_off + 24..ip_off + 40].copy_from_slice(&new_b);
                    changed = true;
                }
            }
        }
    }

    changed
}

// ── Payload truncation ────────────────────────────────────────────────────────

/// Truncate the packet payload to `max_bytes` and update IP/UDP length fields.
///
/// Returns `(new_origlen, did_truncate)`.
fn do_truncate(data: &mut Vec<u8>, max_bytes: u32, origlen: u32) -> (u32, bool) {
    let Some((ip_off, et)) = find_ip(data) else {
        return (origlen, false);
    };

    let (proto, transport_start, transport_hdr_len) = match et {
        ET_IPV4 => {
            if data.len() < ip_off + 20 {
                return (origlen, false);
            }
            let ihl = ((data[ip_off] & 0x0F) * 4) as usize;
            if data.len() < ip_off + ihl {
                return (origlen, false);
            }
            let proto = data[ip_off + 9];
            let ts = ip_off + ihl;
            let th = match proto {
                PROTO_TCP => {
                    if data.len() < ts + 20 {
                        return (origlen, false);
                    }
                    ((data[ts + 12] >> 4) * 4) as usize
                }
                PROTO_UDP => 8,
                _ => return (origlen, false),
            };
            (proto, ts, th)
        }
        ET_IPV6 => {
            if data.len() < ip_off + 40 {
                return (origlen, false);
            }
            let proto = data[ip_off + 6]; // next header
            let ts = ip_off + 40;
            let th = match proto {
                PROTO_TCP => {
                    if data.len() < ts + 20 {
                        return (origlen, false);
                    }
                    ((data[ts + 12] >> 4) * 4) as usize
                }
                PROTO_UDP => 8,
                _ => return (origlen, false),
            };
            (proto, ts, th)
        }
        _ => return (origlen, false),
    };

    let payload_start = transport_start + transport_hdr_len;
    let max_total = payload_start + max_bytes as usize;

    if data.len() <= max_total {
        return (origlen, false); // already short enough
    }

    data.truncate(max_total);
    let new_len = data.len();

    // Update IP total length / payload length.
    if et == ET_IPV4 {
        let new_ip_total = (new_len - ip_off) as u16;
        data[ip_off + 2..ip_off + 4].copy_from_slice(&new_ip_total.to_be_bytes());
    } else {
        // IPv6 payload length = everything after the 40-byte fixed header.
        let new_plen = (new_len - ip_off - 40) as u16;
        data[ip_off + 4..ip_off + 6].copy_from_slice(&new_plen.to_be_bytes());
    }

    // Update UDP length. TCP has no explicit payload length field.
    if proto == PROTO_UDP {
        let new_udp_len = (new_len - transport_start) as u16;
        data[transport_start + 4..transport_start + 6].copy_from_slice(&new_udp_len.to_be_bytes());
    }

    (new_len as u32, true)
}

// ── Checksum recalculation ────────────────────────────────────────────────────

/// Recompute all checksums in `data` (IPv4 header + TCP/UDP transport).
fn recalculate_checksums(data: &mut [u8]) {
    let Some((ip_off, et)) = find_ip(data) else {
        return;
    };
    match et {
        ET_IPV4 => recalc_ipv4(data, ip_off),
        ET_IPV6 => recalc_ipv6(data, ip_off),
        _ => {}
    }
}

fn recalc_ipv4(data: &mut [u8], ip_off: usize) {
    if data.len() < ip_off + 20 {
        return;
    }
    let ihl = ((data[ip_off] & 0x0F) * 4) as usize;
    if data.len() < ip_off + ihl {
        return;
    }

    // Recompute IPv4 header checksum (field at offset 10–12 within the header).
    data[ip_off + 10] = 0;
    data[ip_off + 11] = 0;
    let csum = internet_checksum(&data[ip_off..ip_off + ihl]);
    data[ip_off + 10..ip_off + 12].copy_from_slice(&csum.to_be_bytes());

    let proto = data[ip_off + 9];
    let ts = ip_off + ihl;
    if proto == PROTO_TCP || proto == PROTO_UDP {
        recalc_transport_v4(data, ip_off, ts, proto);
    }
}

fn recalc_transport_v4(data: &mut [u8], ip_off: usize, ts: usize, proto: u8) {
    let csum_off = if proto == PROTO_TCP { ts + 16 } else { ts + 6 };
    if data.len() < csum_off + 2 {
        return;
    }
    let src: [u8; 4] = data[ip_off + 12..ip_off + 16].try_into().unwrap();
    let dst: [u8; 4] = data[ip_off + 16..ip_off + 20].try_into().unwrap();
    data[csum_off] = 0;
    data[csum_off + 1] = 0;
    let csum = transport_checksum_v4(src, dst, proto, &data[ts..]);
    data[csum_off..csum_off + 2].copy_from_slice(&csum.to_be_bytes());
}

fn recalc_ipv6(data: &mut [u8], ip_off: usize) {
    if data.len() < ip_off + 40 {
        return;
    }
    let proto = data[ip_off + 6]; // next header
    let ts = ip_off + 40;
    if proto == PROTO_TCP || proto == PROTO_UDP {
        recalc_transport_v6(data, ip_off, ts, proto);
    }
}

fn recalc_transport_v6(data: &mut [u8], ip_off: usize, ts: usize, proto: u8) {
    let csum_off = if proto == PROTO_TCP { ts + 16 } else { ts + 6 };
    if data.len() < csum_off + 2 {
        return;
    }
    let src: [u8; 16] = data[ip_off + 8..ip_off + 24].try_into().unwrap();
    let dst: [u8; 16] = data[ip_off + 24..ip_off + 40].try_into().unwrap();
    data[csum_off] = 0;
    data[csum_off + 1] = 0;
    let csum = transport_checksum_v6(src, dst, proto, &data[ts..]);
    data[csum_off..csum_off + 2].copy_from_slice(&csum.to_be_bytes());
}

// ── Checksum math ─────────────────────────────────────────────────────────────

/// Standard Internet checksum (RFC 1071): one's complement of the 16-bit ones-complement sum.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut iter = data.chunks_exact(2);
    for chunk in &mut iter {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [byte] = iter.remainder() {
        sum += (*byte as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Transport-layer checksum using an IPv4 pseudo-header.
fn transport_checksum_v4(src: [u8; 4], dst: [u8; 4], proto: u8, segment: &[u8]) -> u16 {
    let len = segment.len() as u32;
    let mut sum: u32 = 0;
    // Pseudo-header: src IP, dst IP, zero, proto, segment length.
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += proto as u32;
    sum += len & 0xFFFF;
    let mut iter = segment.chunks_exact(2);
    for chunk in &mut iter {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [byte] = iter.remainder() {
        sum += (*byte as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Transport-layer checksum using an IPv6 pseudo-header.
fn transport_checksum_v6(src: [u8; 16], dst: [u8; 16], proto: u8, segment: &[u8]) -> u16 {
    let len = segment.len() as u32;
    let mut sum: u32 = 0;
    // src and dst addresses (16 bytes each = 8 words each).
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    // Upper-layer packet length (4 bytes, big-endian).
    sum += len >> 16;
    sum += len & 0xFFFF;
    // Next header (3 zero bytes + 1 byte proto).
    sum += proto as u32;
    let mut iter = segment.chunks_exact(2);
    for chunk in &mut iter {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [byte] = iter.remainder() {
        sum += (*byte as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Frame builders ────────────────────────────────────────────────────────

    fn eth_ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let ip_total = 20 + udp_len;
        let mut f = Vec::new();
        f.extend_from_slice(&[0xFF; 6]); // dst MAC
        f.extend_from_slice(&[0x00; 6]); // src MAC
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        f.push(0x45); // version=4, IHL=5
        f.push(0x00); // DSCP/ECN
        f.extend_from_slice(&ip_total.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // ID, flags/frag
        f.push(64);
        f.push(17); // TTL, UDP
        f.extend_from_slice(&[0x00, 0x00]); // header checksum (zeroed)
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x00]); // UDP checksum
        f.extend_from_slice(payload);
        f
    }

    fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let ip_total = (20 + 20 + payload.len()) as u16;
        let mut f = Vec::new();
        f.extend_from_slice(&[0xFF; 6]);
        f.extend_from_slice(&[0x00; 6]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.push(0x45);
        f.push(0x00);
        f.extend_from_slice(&ip_total.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        f.push(64);
        f.push(6); // TCP
        f.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        // TCP header
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0x00; 4]); // seq
        f.extend_from_slice(&[0x00; 4]); // ack
        f.push(0x50); // data offset=5
        f.push(0x02); // SYN
        f.extend_from_slice(&[0xFF, 0xFF]); // window
        f.extend_from_slice(&[0x00, 0x00]); // checksum
        f.extend_from_slice(&[0x00, 0x00]); // urgent
        f.extend_from_slice(payload);
        f
    }

    // ── parse_ip_mapping ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_ip_mapping_valid_v4() {
        let m = parse_ip_mapping("10.0.0.1=192.168.1.1").unwrap();
        assert_eq!(m.old, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(m.new, "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_ip_mapping_valid_v6() {
        let m = parse_ip_mapping("::1=::2").unwrap();
        assert_eq!(m.old, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(m.new, "::2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_ip_mapping_no_equals() {
        assert!(parse_ip_mapping("10.0.0.1").is_err());
    }

    #[test]
    fn test_parse_ip_mapping_invalid_ip() {
        assert!(parse_ip_mapping("notanip=192.168.1.1").is_err());
    }

    #[test]
    fn test_parse_ip_mapping_cross_family() {
        let err = parse_ip_mapping("10.0.0.1=::1").unwrap_err();
        assert!(matches!(err, TransformError::CrossFamily(_, _)));
    }

    // ── internet_checksum ─────────────────────────────────────────────────────

    #[test]
    fn test_internet_checksum_all_zeros() {
        // One's complement of zero is 0xFFFF.
        assert_eq!(internet_checksum(&[0u8; 20]), 0xFFFF);
    }

    #[test]
    fn test_internet_checksum_verify_roundtrip() {
        // Compute checksum of a zeroed-out IPv4 header, insert it, then
        // re-checking the complete header (including inserted checksum) should
        // yield 0x0000 — the one's complement of the sum 0xFFFF, meaning valid.
        let mut header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, // version/IHL, total length=40
            0x00, 0x01, 0x00, 0x00, // ID, flags
            0x40, 0x06, 0x00, 0x00, // TTL, TCP, checksum=0
            0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x08, 0x08, 0x08, 0x08, // dst 8.8.8.8
        ];
        let csum = internet_checksum(&header);
        header[10] = (csum >> 8) as u8;
        header[11] = (csum & 0xFF) as u8;
        // A valid header's 16-bit word sum = 0xFFFF → !0xFFFF = 0x0000.
        assert_eq!(internet_checksum(&header), 0x0000);
    }

    // ── timestamp shift ───────────────────────────────────────────────────────

    #[test]
    fn test_timestamp_shift_positive() {
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &[]);
        let origlen = data.len() as u32;
        let (new_ts, _, _) = apply(
            &mut data,
            1_000_000_000,
            500_000_000,
            origlen,
            &TransformOptions::default(),
        );
        assert_eq!(new_ts, 1_500_000_000);
    }

    #[test]
    fn test_timestamp_shift_clamped_to_zero() {
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &[]);
        let origlen = data.len() as u32;
        // Delta pushes timestamp below zero → clamp to 0.
        let (new_ts, _, _) = apply(&mut data, 100, -200, origlen, &TransformOptions::default());
        assert_eq!(new_ts, 0);
    }

    // ── no-op ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_no_transform_leaves_data_unchanged() {
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &[0xAA; 10]);
        let original = data.clone();
        let origlen = data.len() as u32;
        let (new_ts, new_caplen, new_origlen) =
            apply(&mut data, 42, 0, origlen, &TransformOptions::default());
        assert_eq!(new_ts, 42);
        assert_eq!(new_caplen, origlen);
        assert_eq!(new_origlen, origlen);
        assert_eq!(data, original);
    }

    // ── IP mapping ────────────────────────────────────────────────────────────

    #[test]
    fn test_ip_mapping_replaces_src_ip() {
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=192.168.1.1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);
        // IPv4 src IP: Ethernet(14) + IP offset 12 = byte 26
        assert_eq!(&data[26..30], &[192, 168, 1, 1]);
        assert_eq!(&data[30..34], &[8, 8, 8, 8]); // dst unchanged
    }

    #[test]
    fn test_ip_mapping_replaces_dst_ip() {
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [10, 0, 0, 2], 1234, 53, &[0u8; 4]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.2=172.16.0.1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);
        assert_eq!(&data[30..34], &[172, 16, 0, 1]);
    }

    #[test]
    fn test_ip_mapping_updates_ipv4_header_checksum() {
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=192.168.1.1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);
        // A valid header: one's complement sum of all words = 0xFFFF → !0xFFFF = 0x0000.
        let ihl = ((data[14] & 0x0F) * 4) as usize;
        assert_eq!(
            internet_checksum(&data[14..14 + ihl]),
            0x0000,
            "IPv4 header checksum must be valid after IP mapping"
        );
    }

    #[test]
    fn test_ip_mapping_no_match_leaves_data_unchanged() {
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &[0xBB; 4]);
        let original = data.clone();
        let origlen = data.len() as u32;
        // Mapping for an IP not present in the packet.
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.99=10.0.0.1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);
        assert_eq!(data, original);
    }

    // ── Payload truncation ────────────────────────────────────────────────────

    #[test]
    fn test_truncation_udp_updates_lengths() {
        let payload = vec![0xBB; 100];
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(10),
            ..Default::default()
        };
        let (_, new_caplen, new_origlen) = apply(&mut data, 0, 0, orig, &opts);

        // Ethernet(14) + IPv4(20) + UDP(8) + 10 = 52
        assert_eq!(data.len(), 52);
        assert_eq!(new_caplen, 52);
        assert_eq!(new_origlen, 52);

        // IPv4 total length: 20 + 8 + 10 = 38
        let ip_total = u16::from_be_bytes([data[16], data[17]]);
        assert_eq!(ip_total, 38, "IPv4 total length not updated");

        // UDP length field is at offset 4 within the UDP header (transport_start=34).
        // 8 + 10 = 18
        let udp_len = u16::from_be_bytes([data[38], data[39]]);
        assert_eq!(udp_len, 18, "UDP length not updated");
    }

    #[test]
    fn test_truncation_tcp_updates_ip_length() {
        let payload = vec![0xCC; 50];
        let mut data = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 100, 443, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(5),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);

        // Ethernet(14) + IPv4(20) + TCP(20) + 5 = 59
        assert_eq!(data.len(), 59);
        // IPv4 total: 20 + 20 + 5 = 45
        let ip_total = u16::from_be_bytes([data[16], data[17]]);
        assert_eq!(ip_total, 45);
    }

    #[test]
    fn test_truncation_noop_when_short_enough() {
        let payload = vec![0xAA; 5];
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &payload);
        let original = data.clone();
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(100),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        assert_eq!(data, original);
    }

    #[test]
    fn test_truncation_checksums_valid() {
        let payload = vec![0xDE; 50];
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(8),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        let ihl = ((data[14] & 0x0F) * 4) as usize;
        assert_eq!(
            internet_checksum(&data[14..14 + ihl]),
            0x0000,
            "IPv4 header checksum must be valid after truncation"
        );
    }

    #[test]
    fn test_truncation_zero_payload_bytes() {
        // max_payload_bytes=0 keeps only headers, no payload.
        let payload = vec![0xFF; 20];
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(0),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        // Ethernet(14) + IPv4(20) + UDP(8) = 42
        assert_eq!(data.len(), 42);
    }

    // ── Combined transforms ───────────────────────────────────────────────────

    #[test]
    fn test_ip_mapping_and_truncation_combined() {
        let payload = vec![0xAB; 80];
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=192.168.99.1").unwrap()],
            max_payload_bytes: Some(16),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);

        // IP was replaced.
        assert_eq!(&data[26..30], &[192, 168, 99, 1]);
        // Length was truncated: 14 + 20 + 8 + 16 = 58.
        assert_eq!(data.len(), 58);
        // Header checksum is valid (word sum = 0xFFFF → !0xFFFF = 0x0000).
        let ihl = ((data[14] & 0x0F) * 4) as usize;
        assert_eq!(internet_checksum(&data[14..14 + ihl]), 0x0000);
    }
}
