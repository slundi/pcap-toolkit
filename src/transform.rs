//! Phase 4: Packet-level transformations applied during the sort second pass.
//!
//! Transformations are applied in this order for each packet:
//! 1. **IP address mapping** — replace IP addresses in-place or re-frame the
//!    packet when the mapping is cross-family (IPv4↔IPv6).
//! 2. **Payload truncation** — shorten the payload and update length fields.
//! 3. **Checksum recalculation** — recompute Layer 3 (IP) and Layer 4 (TCP/UDP)
//!    checksums whenever the above steps modified the packet bytes.
//!
//! Timestamp shifting is computed once before the loop and applied per-packet
//! without touching the byte payload.
//!
//! Only Ethernet frames (link type 1) carrying IPv4 or IPv6 are supported.
//! A single 802.1Q VLAN tag is transparently handled. Other link types and
//! encapsulations are passed through untouched.
//!
//! ## Cross-family IP mapping
//!
//! When a mapping changes the IP version of an address (e.g. `10.0.0.1=::1`),
//! the entire Ethernet payload must be re-framed:
//!
//! - **IPv4 → IPv6**: The packet gains a 40-byte IPv6 header (vs. the original
//!   ≥20-byte IPv4 header). Unmapped IPv4 addresses are embedded as
//!   IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`).
//! - **IPv6 → IPv4**: The packet shrinks by 20 bytes (IPv6 40 B → IPv4 20 B).
//!   Unmapped IPv6 addresses must be IPv4-mapped (`::ffff:a.b.c.d`); if they
//!   are not, the re-frame is skipped and the packet is passed through
//!   unchanged.
//!
//! After re-framing, all checksums are recalculated using the new pseudo-header.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

// ── EtherType / protocol constants ───────────────────────────────────────────

const ET_IPV4: u16 = 0x0800;
const ET_IPV6: u16 = 0x86DD;
const ET_VLAN: u16 = 0x8100;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

// IPv6 extension-header "next header" values that carry their own length field
// and must be walked to reach the real transport. Excludes ESP (50) — its
// payload is encrypted and an opaque blob from our perspective.
const IPV6_EXT_HBH: u8 = 0; // Hop-by-Hop options
const IPV6_EXT_ROUTING: u8 = 43;
const IPV6_EXT_FRAGMENT: u8 = 44;
const IPV6_EXT_AH: u8 = 51; // Authentication Header (length unit differs)
const IPV6_EXT_DEST: u8 = 60; // Destination options
const IPV6_EXT_MOBILITY: u8 = 135;
const IPV6_EXT_HIP: u8 = 139;
const IPV6_EXT_SHIM6: u8 = 140;

/// Walk the IPv6 extension-header chain.
///
/// Starting at the fixed header's next-header byte (`data[ip_off + 6]`),
/// traverse extension headers until a non-extension protocol is reached.
///
/// Returns `Some((final_proto, transport_start))` where `transport_start` is
/// the byte offset of the first non-extension protocol header, or `None` if
/// the chain is malformed or runs off the end of the buffer.
///
/// Caller must have already verified that `data.len() >= ip_off + 40`.
fn walk_ipv6_extension_headers(data: &[u8], ip_off: usize) -> Option<(u8, usize)> {
    debug_assert!(data.len() >= ip_off + 40);
    let mut next = data[ip_off + 6];
    let mut off = ip_off + 40;
    // Bound the loop — pathological/looping chains should not block forever.
    for _ in 0..16 {
        let hdr_len = match next {
            IPV6_EXT_HBH | IPV6_EXT_ROUTING | IPV6_EXT_DEST | IPV6_EXT_MOBILITY | IPV6_EXT_HIP
            | IPV6_EXT_SHIM6 => {
                // Length is "header extension length" in 8-byte units, not
                // counting the first 8 bytes.
                if data.len() < off + 2 {
                    return None;
                }
                8 + (data[off + 1] as usize) * 8
            }
            IPV6_EXT_FRAGMENT => 8, // fixed-size 8-byte header
            IPV6_EXT_AH => {
                // AH "Payload Len" field is in 4-byte units, not counting the
                // first 8 bytes (so total = (len + 2) * 4).
                if data.len() < off + 2 {
                    return None;
                }
                (data[off + 1] as usize + 2) * 4
            }
            _ => return Some((next, off)),
        };
        if data.len() < off + hdr_len {
            return None;
        }
        next = data[off];
        off += hdr_len;
    }
    None
}

// ── Public types ─────────────────────────────────────────────────────────────

/// Errors produced during transform option parsing.
#[derive(Debug, Error)]
pub enum TransformError {
    #[error("invalid IP mapping '{0}': expected OLD_IP=NEW_IP")]
    InvalidMapping(String),
}

/// One IP address replacement rule.
#[derive(Debug, Clone)]
pub struct IpMapping {
    /// Address to search for in packet headers.
    pub old: IpAddr,
    /// Address to write in place of `old`.
    pub new: IpAddr,
}

/// A per-protocol payload truncation rule.
///
/// When the packet's IP protocol matches `proto`, the payload is truncated to
/// at most `max_payload_bytes` bytes. Per-protocol rules take precedence over
/// the global [`TransformOptions::max_payload_bytes`] limit.
#[derive(Debug, Clone)]
pub struct ProtocolTruncation {
    /// IP protocol number (e.g. `6` = TCP, `17` = UDP).
    pub proto: u8,
    /// Maximum payload bytes to keep for this protocol.
    pub max_payload_bytes: u32,
}

/// All packet-level transformation options for a sort run.
#[derive(Debug, Default, Clone)]
pub struct TransformOptions {
    /// Truncate the payload of each packet to at most this many bytes.
    /// Ethernet, IP, and transport headers are always preserved.
    ///
    /// Overridden per-protocol by [`proto_truncation`](Self::proto_truncation).
    pub max_payload_bytes: Option<u32>,
    /// When set, all timestamps are shifted so the first sorted packet starts
    /// at exactly this nanosecond epoch value.
    ///
    /// The delta is computed once in [`second_pass`] and passed as `ts_delta`.
    pub timestamp_start_ns: Option<u64>,
    /// IP address replacement rules, evaluated in order for every packet.
    ///
    /// Rules are applied **sequentially within a single pass**, so an earlier
    /// rule's `new` address is visible to later rules. With mappings
    /// `[A=B, B=C]`, an address `A` is rewritten to `B` by the first rule and
    /// then to `C` by the second — i.e. substitutions chain. If you want
    /// independent substitutions, order the rules so earlier `new` values are
    /// never the input of a later rule, or use disjoint address ranges.
    pub ip_map: Vec<IpMapping>,
    /// Per-protocol payload truncation rules (TOML: `[[transform.truncate_by_proto]]`).
    ///
    /// The first rule whose `proto` matches the packet's IP protocol is used.
    /// Falls back to [`max_payload_bytes`](Self::max_payload_bytes) when no
    /// rule matches.
    pub proto_truncation: Vec<ProtocolTruncation>,
}

impl TransformOptions {
    /// Returns `true` when no transformations are configured.
    pub fn is_empty(&self) -> bool {
        self.max_payload_bytes.is_none()
            && self.timestamp_start_ns.is_none()
            && self.ip_map.is_empty()
            && self.proto_truncation.is_empty()
    }
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Parse `"OLD_IP=NEW_IP"` into an [`IpMapping`].
///
/// Both sides must be valid IP addresses. Cross-family mappings (IPv4↔IPv6)
/// are supported and will cause the entire Ethernet payload to be re-framed
/// when applied; see the module-level documentation for details.
///
/// # Errors
/// [`TransformError::InvalidMapping`] — format wrong or address unparsable.
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

    let (ip_changed, reframed) = if !opts.ip_map.is_empty() {
        apply_ip_map(data, &opts.ip_map)
    } else {
        (false, false)
    };

    // After a cross-family re-frame the packet length changes, so origlen must
    // be updated to the new frame size before the truncation step.
    let origlen = if reframed { data.len() as u32 } else { origlen };

    let (new_origlen, truncated) = match effective_truncation_limit(data, opts) {
        Some(max_bytes) => do_truncate(data, max_bytes, origlen),
        None => (origlen, false),
    };

    if ip_changed || truncated {
        recalculate_checksums(data);
    }

    let new_caplen = data.len() as u32;
    (new_ts, new_caplen, new_origlen)
}

// ── Truncation limit resolution ───────────────────────────────────────────────

/// Return the IP protocol number from an Ethernet frame, if parseable.
fn detect_protocol(data: &[u8]) -> Option<u8> {
    let (ip_off, et) = find_ip(data)?;
    match et {
        ET_IPV4 => {
            if data.len() >= ip_off + 20 {
                Some(data[ip_off + 9])
            } else {
                None
            }
        }
        ET_IPV6 => {
            if data.len() >= ip_off + 40 {
                // Walk extension headers so per-protocol truncation rules fire
                // on the real transport protocol, not the first ext-header.
                walk_ipv6_extension_headers(data, ip_off).map(|(proto, _)| proto)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Determine the effective payload truncation limit for one packet.
///
/// Per-protocol rules are checked first; the first matching rule wins.
/// Falls back to the global `max_payload_bytes` when no rule matches.
fn effective_truncation_limit(data: &[u8], opts: &TransformOptions) -> Option<u32> {
    if !opts.proto_truncation.is_empty()
        && let Some(proto) = detect_protocol(data)
    {
        for rule in &opts.proto_truncation {
            if rule.proto == proto {
                return Some(rule.max_payload_bytes);
            }
        }
    }
    opts.max_payload_bytes
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
/// Returns `(changed, reframed)`:
/// - `changed` — `true` if at least one address was modified.
/// - `reframed` — `true` if the packet was re-framed to a different IP version
///   (origlen must be updated by the caller).
fn apply_ip_map(data: &mut Vec<u8>, mappings: &[IpMapping]) -> (bool, bool) {
    let Some((ip_off, et)) = find_ip(data) else {
        return (false, false);
    };

    // Fast path: if no cross-family mappings exist, skip reframe logic.
    let has_cross = mappings.iter().any(|m| {
        matches!(
            (&m.old, &m.new),
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_))
        )
    });

    if has_cross {
        if et == ET_IPV4 && needs_v4_to_v6_reframe(data, ip_off, mappings) {
            if let Some(new_data) = reframe_ipv4_to_ipv6(data, ip_off, mappings) {
                *data = new_data;
                return (true, true);
            }
        } else if et == ET_IPV6
            && needs_v6_to_v4_reframe(data, ip_off, mappings)
            && let Some(new_data) = reframe_ipv6_to_ipv4(data, ip_off, mappings)
        {
            *data = new_data;
            return (true, true);
        }
    }

    // Same-family in-place replacements.
    let mut changed = false;

    if et == ET_IPV4 {
        if data.len() < ip_off + 20 {
            return (false, false);
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
            return (false, false);
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

    (changed, false)
}

// ── Cross-family reframing ────────────────────────────────────────────────────

/// Return `true` if the IPv4 packet's src or dst matches a v4→v6 mapping.
fn needs_v4_to_v6_reframe(data: &[u8], ip_off: usize, mappings: &[IpMapping]) -> bool {
    if data.len() < ip_off + 20 {
        return false;
    }
    let src = &data[ip_off + 12..ip_off + 16];
    let dst = &data[ip_off + 16..ip_off + 20];
    mappings.iter().any(|m| {
        if let (IpAddr::V4(old), IpAddr::V6(_)) = (&m.old, &m.new) {
            let b = old.octets();
            src == b || dst == b
        } else {
            false
        }
    })
}

/// Return `true` if the IPv6 packet's src or dst matches a v6→v4 mapping.
fn needs_v6_to_v4_reframe(data: &[u8], ip_off: usize, mappings: &[IpMapping]) -> bool {
    if data.len() < ip_off + 40 {
        return false;
    }
    let src = &data[ip_off + 8..ip_off + 24];
    let dst = &data[ip_off + 24..ip_off + 40];
    mappings.iter().any(|m| {
        if let (IpAddr::V6(old), IpAddr::V4(_)) = (&m.old, &m.new) {
            let b = old.octets();
            src == b || dst == b
        } else {
            false
        }
    })
}

/// Re-frame an IPv4 Ethernet packet as IPv6.
///
/// Applies v4→v6 (and v4→v4) mappings to both addresses. Unmapped IPv4
/// addresses are embedded as `::ffff:a.b.c.d`.
///
/// Returns `None` if the packet is malformed.
fn reframe_ipv4_to_ipv6(data: &[u8], ip_off: usize, mappings: &[IpMapping]) -> Option<Vec<u8>> {
    if data.len() < ip_off + 20 {
        return None;
    }
    // Raw IHL field is the header length in 32-bit words. Minimum legal value
    // is 5 (= 20 bytes); anything less is malformed and would cause us to
    // misread "transport" bytes from inside the IP header.
    let raw_ihl = data[ip_off] & 0x0F;
    if raw_ihl < 5 {
        return None;
    }
    let ihl = (raw_ihl as usize) * 4;
    if data.len() < ip_off + ihl {
        return None;
    }

    let ttl = data[ip_off + 8];
    let proto = data[ip_off + 9];
    let src_v4 = Ipv4Addr::from(<[u8; 4]>::try_from(&data[ip_off + 12..ip_off + 16]).ok()?);
    let dst_v4 = Ipv4Addr::from(<[u8; 4]>::try_from(&data[ip_off + 16..ip_off + 20]).ok()?);

    let src_v6 = resolve_ipv4_to_ipv6(src_v4, mappings);
    let dst_v6 = resolve_ipv4_to_ipv6(dst_v4, mappings);

    let transport = &data[ip_off + ihl..];
    // IPv6 payload length is a 16-bit field; refuse to silently wrap.
    let payload_len: u16 = transport.len().try_into().ok()?;

    let mut out = Vec::with_capacity(ip_off + 40 + transport.len());
    write_ethernet_preamble(&mut out, data, ip_off, ET_IPV6);

    // IPv6 fixed header (40 bytes).
    out.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6, TC=0, flow=0
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.push(proto); // next header
    out.push(ttl); // hop limit
    out.extend_from_slice(&src_v6);
    out.extend_from_slice(&dst_v6);

    // Transport + payload verbatim; checksums recalculated by caller.
    out.extend_from_slice(transport);

    Some(out)
}

/// Re-frame an IPv6 Ethernet packet as IPv4.
///
/// Applies v6→v4 (and v6→v6) mappings to both addresses. Unmapped IPv6
/// addresses must be IPv4-mapped (`::ffff:a.b.c.d`); if they are not, the
/// re-frame is skipped and `None` is returned.
///
/// Returns `None` if the packet is malformed or cannot be converted cleanly.
fn reframe_ipv6_to_ipv4(data: &[u8], ip_off: usize, mappings: &[IpMapping]) -> Option<Vec<u8>> {
    if data.len() < ip_off + 40 {
        return None;
    }

    let hop_limit = data[ip_off + 7]; // → TTL
    // Refuse to reframe packets carrying IPv6 extension headers — they have
    // no direct IPv4 equivalent and copying the bytes verbatim would mismatch
    // the rewritten `protocol` field.
    let (proto, transport_start) = walk_ipv6_extension_headers(data, ip_off)?;
    if transport_start != ip_off + 40 {
        return None;
    }
    let src_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(&data[ip_off + 8..ip_off + 24]).ok()?);
    let dst_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(&data[ip_off + 24..ip_off + 40]).ok()?);

    // Both addresses must resolve to IPv4; otherwise skip.
    let src_v4 = resolve_ipv6_to_ipv4(src_v6, mappings)?;
    let dst_v4 = resolve_ipv6_to_ipv4(dst_v6, mappings)?;

    let transport = &data[ip_off + 40..];
    // IPv4 total-length is a 16-bit field; bail if the rewritten packet
    // would overflow rather than producing a silently-wrapped header.
    let ip_total: u16 = (20usize)
        .checked_add(transport.len())
        .and_then(|n| n.try_into().ok())?;

    let mut out = Vec::with_capacity(ip_off + 20 + transport.len());
    write_ethernet_preamble(&mut out, data, ip_off, ET_IPV4);

    // IPv4 header (20 bytes, no options).
    out.push(0x45); // version=4, IHL=5
    out.push(0x00); // DSCP/ECN
    out.extend_from_slice(&ip_total.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // identification
    out.extend_from_slice(&[0x40, 0x00]); // DF flag, fragment offset=0
    out.push(hop_limit); // TTL
    out.push(proto); // protocol
    out.extend_from_slice(&[0x00, 0x00]); // checksum — recalculated by caller
    out.extend_from_slice(&src_v4);
    out.extend_from_slice(&dst_v4);

    // Transport + payload verbatim; checksums recalculated by caller.
    out.extend_from_slice(transport);

    Some(out)
}

/// Write the Ethernet preamble (MACs + EtherType, with optional VLAN tag) into `out`.
///
/// `ip_off` is 14 for untagged frames and 18 for 802.1Q-tagged frames.
fn write_ethernet_preamble(out: &mut Vec<u8>, src: &[u8], ip_off: usize, ethertype: u16) {
    out.extend_from_slice(&src[0..12]); // dst MAC + src MAC
    if ip_off == 18 {
        out.extend_from_slice(&src[12..16]); // 0x8100 + VLAN TCI
        out.extend_from_slice(&ethertype.to_be_bytes()); // inner EtherType
    } else {
        out.extend_from_slice(&ethertype.to_be_bytes());
    }
}

/// Resolve an IPv4 address to its IPv6 representation after applying mappings.
///
/// Priority:
/// 1. A matching v4→v6 mapping → use the mapped IPv6 address directly.
/// 2. A matching v4→v4 mapping → embed the new IPv4 as `::ffff:new_v4`.
/// 3. No mapping → embed the original as `::ffff:addr`.
fn resolve_ipv4_to_ipv6(addr: Ipv4Addr, mappings: &[IpMapping]) -> [u8; 16] {
    for m in mappings {
        match (&m.old, &m.new) {
            (IpAddr::V4(old), IpAddr::V6(new)) if *old == addr => return new.octets(),
            (IpAddr::V4(old), IpAddr::V4(new)) if *old == addr => {
                return ipv4_mapped_to_ipv6(new.octets());
            }
            _ => {}
        }
    }
    ipv4_mapped_to_ipv6(addr.octets())
}

/// Resolve an IPv6 address to its IPv4 representation after applying mappings.
///
/// Priority:
/// 1. A matching v6→v4 mapping → use the mapped IPv4 address directly.
/// 2. A matching v6→v6 mapping → try to extract IPv4 from an IPv4-mapped result.
/// 3. No mapping → try to extract IPv4 from an IPv4-mapped address (`::ffff:…`).
///
/// Returns `None` if the address cannot be expressed as IPv4.
fn resolve_ipv6_to_ipv4(addr: Ipv6Addr, mappings: &[IpMapping]) -> Option<[u8; 4]> {
    for m in mappings {
        match (&m.old, &m.new) {
            (IpAddr::V6(old), IpAddr::V4(new)) if *old == addr => return Some(new.octets()),
            (IpAddr::V6(old), IpAddr::V6(new)) if *old == addr => {
                return new.to_ipv4_mapped().map(|v4| v4.octets());
            }
            _ => {}
        }
    }
    addr.to_ipv4_mapped().map(|v4| v4.octets())
}

/// Embed an IPv4 address as an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
fn ipv4_mapped_to_ipv6(v4: [u8; 4]) -> [u8; 16] {
    let mut v6 = [0u8; 16];
    v6[10] = 0xFF;
    v6[11] = 0xFF;
    v6[12..16].copy_from_slice(&v4);
    v6
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
                    let th = ((data[ts + 12] >> 4) * 4) as usize;
                    if th < 20 {
                        return (origlen, false);
                    }
                    th
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
            // Walk extension headers to find the real transport. Bail on
            // unparsable chains rather than truncating into ext-header bytes.
            let Some((proto, ts)) = walk_ipv6_extension_headers(data, ip_off) else {
                return (origlen, false);
            };
            let th = match proto {
                PROTO_TCP => {
                    if data.len() < ts + 20 {
                        return (origlen, false);
                    }
                    let th = ((data[ts + 12] >> 4) * 4) as usize;
                    if th < 20 {
                        return (origlen, false);
                    }
                    th
                }
                PROTO_UDP => 8,
                _ => return (origlen, false),
            };
            (proto, ts, th)
        }
        _ => return (origlen, false),
    };

    let payload_start = transport_start + transport_hdr_len;
    // Cap max_total so every length field we have to rewrite still fits in
    // its 16-bit slot. Without this, a large `max_bytes` could produce
    // ip_total / payload_len / udp_len wraparounds and a malformed packet.
    let len_ceiling = if et == ET_IPV4 {
        ip_off + u16::MAX as usize // IP total length
    } else {
        ip_off + 40 + u16::MAX as usize // IPv6 payload length
    };
    let mut max_total = payload_start.saturating_add(max_bytes as usize);
    max_total = max_total.min(len_ceiling);
    if proto == PROTO_UDP {
        // UDP length field is also u16, including the 8-byte header.
        max_total = max_total.min(transport_start + u16::MAX as usize);
    }

    if data.len() <= max_total {
        return (origlen, false); // already short enough
    }

    data.truncate(max_total);
    let new_len = data.len();

    // Update IP total length / payload length. Casts are safe because of the
    // ceiling clamp above.
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
    // Walk past any extension headers; the pseudo-header for the L4 checksum
    // uses the *upper-layer* protocol, not the first ext-header value.
    let Some((proto, ts)) = walk_ipv6_extension_headers(data, ip_off) else {
        return;
    };
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

    /// Build an Ethernet/IPv6/UDP frame.
    fn eth_ipv6_udp(
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let payload_len = udp_len; // IPv6 payload length = transport + data
        let mut f = Vec::new();
        f.extend_from_slice(&[0xFF; 6]); // dst MAC
        f.extend_from_slice(&[0x00; 6]); // src MAC
        f.extend_from_slice(&[0x86, 0xDD]); // IPv6
        f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6, TC=0, flow=0
        f.extend_from_slice(&payload_len.to_be_bytes());
        f.push(17); // next header = UDP
        f.push(64); // hop limit
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x00]); // UDP checksum
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
    fn test_parse_ip_mapping_cross_family_v4_to_v6() {
        // Cross-family mappings are now supported.
        let m = parse_ip_mapping("10.0.0.1=::1").unwrap();
        assert_eq!(m.old, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(m.new, "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_ip_mapping_cross_family_v6_to_v4() {
        let m = parse_ip_mapping("2001:db8::1=192.168.1.1").unwrap();
        assert_eq!(m.old, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(m.new, "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_ip_mapping_no_equals() {
        assert!(parse_ip_mapping("10.0.0.1").is_err());
    }

    #[test]
    fn test_parse_ip_mapping_invalid_ip() {
        assert!(parse_ip_mapping("notanip=192.168.1.1").is_err());
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

    // ── Same-family IP mapping ────────────────────────────────────────────────

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
    fn test_ip_mapping_rules_chain_within_one_pass() {
        // Documented behavior: rules are applied sequentially in a single pass,
        // so [A=B, B=C] rewrites A → B → C in one go. This test pins that
        // semantics down so a future change can't quietly switch to disjoint
        // application without updating the docs.
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![
                parse_ip_mapping("10.0.0.1=192.168.1.1").unwrap(),
                parse_ip_mapping("192.168.1.1=172.16.0.1").unwrap(),
            ],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);
        // Final value reflects both substitutions (A → B → C).
        assert_eq!(&data[26..30], &[172, 16, 0, 1]);
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

    // ── Cross-family reframe: IPv4 → IPv6 ────────────────────────────────────

    #[test]
    fn test_cross_family_ipv4_to_ipv6_src_mapped() {
        // IPv4 packet, src=10.0.0.1, dst=8.8.8.8
        // Mapping: 10.0.0.1 → 2001:db8::1 (v4→v6)
        // Expected: IPv6 packet, src=2001:db8::1, dst=::ffff:8.8.8.8
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0xAB; 4]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=2001:db8::1").unwrap()],
            ..Default::default()
        };
        let (_, new_caplen, new_origlen) = apply(&mut data, 0, 0, origlen, &opts);

        // EtherType must be IPv6.
        assert_eq!(u16::from_be_bytes([data[12], data[13]]), ET_IPV6);
        // IPv6 header: version nibble.
        assert_eq!(data[14] >> 4, 6);
        // src address at offset 22: must be 2001:db8::1
        let src_v6: Ipv6Addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[22..38]).unwrap());
        assert_eq!(src_v6, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        // dst address at offset 38: must be ::ffff:8.8.8.8
        let dst_v6: Ipv6Addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[38..54]).unwrap());
        assert_eq!(dst_v6, "::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap());
        // Payload is preserved: 4 bytes 0xAB at the end.
        assert_eq!(&data[data.len() - 4..], &[0xAB; 4]);
        // Lengths were updated.
        assert_eq!(new_caplen, data.len() as u32);
        assert_eq!(new_origlen, data.len() as u32);
    }

    #[test]
    fn test_cross_family_ipv4_to_ipv6_dst_mapped() {
        // IPv4 packet, src=1.2.3.4, dst=10.0.0.2
        // Mapping: 10.0.0.2 → ::1 (v4→v6)
        // Expected: IPv6 packet, src=::ffff:1.2.3.4, dst=::1
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [10, 0, 0, 2], 5000, 80, &[]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.2=::1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);

        assert_eq!(u16::from_be_bytes([data[12], data[13]]), ET_IPV6);
        let src_v6: Ipv6Addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[22..38]).unwrap());
        assert_eq!(src_v6, "::ffff:1.2.3.4".parse::<Ipv6Addr>().unwrap());
        let dst_v6: Ipv6Addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[38..54]).unwrap());
        assert_eq!(dst_v6, "::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_cross_family_ipv4_to_ipv6_both_mapped() {
        // Both src and dst are mapped to IPv6 addresses.
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 2000, &[0xCC; 8]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![
                parse_ip_mapping("10.0.0.1=2001:db8::1").unwrap(),
                parse_ip_mapping("10.0.0.2=2001:db8::2").unwrap(),
            ],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);

        assert_eq!(u16::from_be_bytes([data[12], data[13]]), ET_IPV6);
        let src_v6: Ipv6Addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[22..38]).unwrap());
        let dst_v6: Ipv6Addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[38..54]).unwrap());
        assert_eq!(src_v6, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(dst_v6, "2001:db8::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_cross_family_ipv4_to_ipv6_checksum_valid() {
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0xDE; 16]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=2001:db8::1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);

        // Verify that the UDP checksum in the IPv6 packet is non-zero (was computed).
        // Transport starts at byte 54 (14 Ethernet + 40 IPv6).
        let udp_csum = u16::from_be_bytes([data[54 + 6], data[54 + 7]]);
        assert_ne!(udp_csum, 0, "UDP checksum must be set in IPv6 packet");
    }

    #[test]
    fn test_cross_family_ipv4_to_ipv6_size_change() {
        // IPv4 → IPv6 adds (40 - 20) = 20 bytes to the IP header.
        let payload = [0u8; 10];
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1000, 2000, &payload);
        let ipv4_len = data.len();
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=::1").unwrap()],
            ..Default::default()
        };
        let (_, new_caplen, new_origlen) = apply(&mut data, 0, 0, origlen, &opts);

        // 14 (Eth) + 40 (IPv6) + 8 (UDP) + 10 (payload) = 72
        // Original: 14 (Eth) + 20 (IPv4) + 8 (UDP) + 10 (payload) = 52
        assert_eq!(data.len(), ipv4_len + 20);
        assert_eq!(new_caplen, data.len() as u32);
        assert_eq!(new_origlen, data.len() as u32);
    }

    // ── Cross-family reframe: IPv6 → IPv4 ────────────────────────────────────

    #[test]
    fn test_cross_family_ipv6_to_ipv4_src_mapped() {
        // IPv6 packet, src=2001:db8::1, dst=::ffff:8.8.8.8
        // Mapping: 2001:db8::1 → 10.0.0.1 (v6→v4)
        let src_v6: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let dst_v6: [u8; 16] = "::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap().octets();
        let mut data = eth_ipv6_udp(src_v6, dst_v6, 5000, 80, &[0xBB; 4]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("2001:db8::1=10.0.0.1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);

        // EtherType must be IPv4.
        assert_eq!(u16::from_be_bytes([data[12], data[13]]), ET_IPV4);
        assert_eq!(data[14] >> 4, 4);
        // src IP at offset 26: 10.0.0.1
        assert_eq!(&data[26..30], &[10, 0, 0, 1]);
        // dst IP at offset 30: 8.8.8.8 (extracted from ::ffff:8.8.8.8)
        assert_eq!(&data[30..34], &[8, 8, 8, 8]);
        // Payload preserved.
        assert_eq!(&data[data.len() - 4..], &[0xBB; 4]);
    }

    #[test]
    fn test_cross_family_ipv6_to_ipv4_dst_mapped() {
        // IPv6 packet, src=::ffff:1.2.3.4, dst=2001:db8::2
        // Mapping: 2001:db8::2 → 192.168.1.2 (v6→v4)
        let src_v6: [u8; 16] = "::ffff:1.2.3.4".parse::<Ipv6Addr>().unwrap().octets();
        let dst_v6: [u8; 16] = "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets();
        let mut data = eth_ipv6_udp(src_v6, dst_v6, 1234, 443, &[]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("2001:db8::2=192.168.1.2").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);

        assert_eq!(u16::from_be_bytes([data[12], data[13]]), ET_IPV4);
        assert_eq!(&data[26..30], &[1, 2, 3, 4]); // extracted from ::ffff:1.2.3.4
        assert_eq!(&data[30..34], &[192, 168, 1, 2]);
    }

    #[test]
    fn test_cross_family_ipv6_to_ipv4_skipped_when_non_mapped_addr() {
        // IPv6 packet where dst is a native IPv6 addr (not IPv4-mapped) and
        // not covered by any mapping → reframe must be skipped.
        let src_v6: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let dst_v6: [u8; 16] = "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets();
        let mut data = eth_ipv6_udp(src_v6, dst_v6, 1000, 2000, &[0xFF; 4]);
        let original = data.clone();
        let origlen = data.len() as u32;
        // Mapping only covers src; dst is a native IPv6 addr with no mapping → skip.
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("2001:db8::1=10.0.0.1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);
        // Packet must be unchanged (reframe was skipped).
        assert_eq!(data, original);
    }

    #[test]
    fn test_cross_family_ipv6_to_ipv4_checksum_valid() {
        let src_v6: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let dst_v6: [u8; 16] = "::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap().octets();
        let mut data = eth_ipv6_udp(src_v6, dst_v6, 5000, 53, &[0xDE; 8]);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("2001:db8::1=10.0.0.1").unwrap()],
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);

        assert_eq!(u16::from_be_bytes([data[12], data[13]]), ET_IPV4);
        let ihl = ((data[14] & 0x0F) * 4) as usize;
        assert_eq!(
            internet_checksum(&data[14..14 + ihl]),
            0x0000,
            "IPv4 header checksum must be valid after v6→v4 reframe"
        );
    }

    #[test]
    fn test_cross_family_ipv6_to_ipv4_size_change() {
        // IPv6 → IPv4 removes 20 bytes (40-byte header → 20-byte header).
        let src_v6: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let dst_v6: [u8; 16] = "::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap().octets();
        let mut data = eth_ipv6_udp(src_v6, dst_v6, 1000, 2000, &[0u8; 10]);
        let ipv6_len = data.len();
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("2001:db8::1=10.0.0.1").unwrap()],
            ..Default::default()
        };
        let (_, new_caplen, new_origlen) = apply(&mut data, 0, 0, origlen, &opts);
        assert_eq!(data.len(), ipv6_len - 20);
        assert_eq!(new_caplen, data.len() as u32);
        assert_eq!(new_origlen, data.len() as u32);
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

    // ── Per-protocol truncation ───────────────────────────────────────────────

    #[test]
    fn test_proto_truncation_tcp_uses_rule() {
        let payload = vec![0xAA; 100];
        let mut data = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 100, 443, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            proto_truncation: vec![ProtocolTruncation {
                proto: PROTO_TCP,
                max_payload_bytes: 10,
            }],
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        // Ethernet(14) + IPv4(20) + TCP(20) + 10 = 64
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn test_proto_truncation_udp_uses_rule() {
        let payload = vec![0xBB; 80];
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 53, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            proto_truncation: vec![ProtocolTruncation {
                proto: PROTO_UDP,
                max_payload_bytes: 8,
            }],
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        // Ethernet(14) + IPv4(20) + UDP(8) + 8 = 50
        assert_eq!(data.len(), 50);
    }

    #[test]
    fn test_proto_truncation_overrides_global() {
        // TCP rule (10 bytes) should win over global limit (50 bytes).
        let payload = vec![0xCC; 100];
        let mut data = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 100, 80, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(50),
            proto_truncation: vec![ProtocolTruncation {
                proto: PROTO_TCP,
                max_payload_bytes: 10,
            }],
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        // Ethernet(14) + IPv4(20) + TCP(20) + 10 = 64
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn test_proto_truncation_fallback_to_global() {
        // No rule for UDP → falls back to global 20 bytes.
        let payload = vec![0xDD; 80];
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 53, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(20),
            proto_truncation: vec![ProtocolTruncation {
                proto: PROTO_TCP, // TCP rule only, no UDP rule
                max_payload_bytes: 5,
            }],
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        // Ethernet(14) + IPv4(20) + UDP(8) + 20 = 62
        assert_eq!(data.len(), 62);
    }

    #[test]
    fn test_proto_truncation_no_match_no_global_no_truncation() {
        // UDP packet, only a TCP rule, no global — no truncation applied.
        let payload = vec![0xEE; 50];
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 53, &payload);
        let original = data.clone();
        let orig = data.len() as u32;
        let opts = TransformOptions {
            proto_truncation: vec![ProtocolTruncation {
                proto: PROTO_TCP,
                max_payload_bytes: 10,
            }],
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        assert_eq!(data, original);
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

    #[test]
    fn test_cross_family_and_truncation_combined() {
        // IPv4 → IPv6 reframe, then truncate payload.
        let payload = vec![0xCD; 100];
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &payload);
        let orig = data.len() as u32;
        let opts = TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=2001:db8::1").unwrap()],
            max_payload_bytes: Some(10),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);

        // Must be an IPv6 packet.
        assert_eq!(u16::from_be_bytes([data[12], data[13]]), ET_IPV6);
        // Ethernet(14) + IPv6(40) + UDP(8) + 10 = 72
        assert_eq!(data.len(), 72);
    }

    // ── Corrupt TCP data-offset ───────────────────────────────────────────────

    #[test]
    fn test_truncation_tcp_corrupt_data_offset_ipv4_rejected() {
        // Build a valid IPv4/TCP frame, then corrupt the data-offset nibble to 4
        // (16 bytes < 20-byte minimum). Truncation must be skipped entirely.
        let mut data = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 100, 443, &[0xAA; 30]);
        // TCP data-offset byte: Ethernet(14) + IPv4(20) + TCP offset 12 = index 46.
        // Nibble 4 → 4*4 = 16 bytes, which is below the 20-byte minimum.
        data[46] = 0x40;
        let original = data.clone();
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(0),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        assert_eq!(
            data, original,
            "corrupt data-offset must leave packet unchanged"
        );
    }

    #[test]
    fn test_truncation_tcp_corrupt_data_offset_ipv6_rejected() {
        // Same check for an IPv6/TCP frame.
        // Build frame manually: Ethernet(14) + IPv6(40) + TCP(20) + payload.
        let payload = [0xBB; 30];
        let tcp_len = (20 + payload.len()) as u16;
        let mut f = Vec::new();
        f.extend_from_slice(&[0xFF; 6]); // dst MAC
        f.extend_from_slice(&[0x00; 6]); // src MAC
        f.extend_from_slice(&[0x86, 0xDD]); // IPv6
        f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6
        f.extend_from_slice(&tcp_len.to_be_bytes()); // payload length
        f.push(6); // next header = TCP
        f.push(64); // hop limit
        f.extend_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
        f.extend_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst
        // TCP header (20 bytes)
        f.extend_from_slice(&100u16.to_be_bytes()); // sport
        f.extend_from_slice(&443u16.to_be_bytes()); // dport
        f.extend_from_slice(&[0x00; 4]); // seq
        f.extend_from_slice(&[0x00; 4]); // ack
        f.push(0x50); // data offset = 5 (will be corrupted below)
        f.push(0x02); // SYN
        f.extend_from_slice(&[0xFF, 0xFF]); // window
        f.extend_from_slice(&[0x00, 0x00]); // checksum
        f.extend_from_slice(&[0x00, 0x00]); // urgent
        f.extend_from_slice(&payload);
        // TCP data-offset byte: Ethernet(14) + IPv6(40) + TCP offset 12 = index 66.
        f[66] = 0x30; // nibble 3 → 3*4 = 12 bytes < 20-byte minimum
        let original = f.clone();
        let orig = f.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(0),
            ..Default::default()
        };
        apply(&mut f, 0, 0, orig, &opts);
        assert_eq!(
            f, original,
            "corrupt data-offset must leave packet unchanged"
        );
    }

    #[test]
    fn test_truncation_tcp_zero_data_offset_rejected() {
        // data-offset nibble = 0 → th = 0, which is also < 20.
        let mut data = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 100, 80, &[0xCC; 10]);
        data[46] = 0x00;
        let original = data.clone();
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(0),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        assert_eq!(data, original);
    }

    #[test]
    fn test_truncation_tcp_min_valid_data_offset_accepted() {
        // data-offset nibble = 5 → th = 20 bytes (minimum valid). Truncation
        // must proceed normally.
        let payload = vec![0xDD; 50];
        let mut data = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 100, 443, &payload);
        // data[46] is already 0x50 (offset = 5) from the helper.
        let orig = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(10),
            ..Default::default()
        };
        apply(&mut data, 0, 0, orig, &opts);
        // Ethernet(14) + IPv4(20) + TCP(20) + 10 = 64
        assert_eq!(data.len(), 64);
    }

    // ── IPv6 extension-header handling ────────────────────────────────────────

    /// Build an IPv6/UDP frame with one Hop-by-Hop extension header in front.
    fn eth_ipv6_hbh_udp(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        // HBH header: next=UDP(17), hdr_ext_len=0 (→ 8 bytes total), 6 bytes of
        // padding (PadN option type 0x01 with len 4 + 4 pad bytes).
        let hbh = [17u8, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00];
        let udp_len = (8 + payload.len()) as u16;
        let payload_len = (hbh.len() as u16) + udp_len;
        let mut f = Vec::new();
        f.extend_from_slice(&[0xFF; 6]);
        f.extend_from_slice(&[0x00; 6]);
        f.extend_from_slice(&[0x86, 0xDD]);
        f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        f.extend_from_slice(&payload_len.to_be_bytes());
        f.push(0); // next header = HBH
        f.push(64);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&hbh);
        f.extend_from_slice(&100u16.to_be_bytes()); // src port
        f.extend_from_slice(&200u16.to_be_bytes()); // dst port
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x00]); // checksum (recomputed by transform)
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn test_walk_ipv6_no_extensions() {
        let frame = eth_ipv6_udp([1; 16], [2; 16], 1, 2, b"hi");
        let (proto, ts) = walk_ipv6_extension_headers(&frame, 14).unwrap();
        assert_eq!(proto, PROTO_UDP);
        assert_eq!(ts, 14 + 40);
    }

    #[test]
    fn test_walk_ipv6_skips_hbh() {
        let frame = eth_ipv6_hbh_udp([1; 16], [2; 16], b"hi");
        let (proto, ts) = walk_ipv6_extension_headers(&frame, 14).unwrap();
        assert_eq!(proto, PROTO_UDP);
        // HBH is 8 bytes long → transport starts 8 bytes past the fixed header.
        assert_eq!(ts, 14 + 40 + 8);
    }

    #[test]
    fn test_walk_ipv6_truncated_ext_header_errors() {
        // Fixed header says next=HBH but the buffer ends right after it.
        let mut frame = eth_ipv6_udp([1; 16], [2; 16], 1, 2, b"x");
        frame[14 + 6] = 0; // next header = HBH
        frame.truncate(14 + 40 + 1); // truncate inside the HBH header
        assert!(walk_ipv6_extension_headers(&frame, 14).is_none());
    }

    #[test]
    fn test_truncation_with_ipv6_ext_header_preserves_transport() {
        // Bug regression: previously the next-header byte (0 = HBH) was
        // treated as TCP/UDP, causing truncate_payload to bail OR worse,
        // splice into the HBH bytes. With the walker, truncation correctly
        // identifies UDP and trims only the payload.
        let payload = vec![0xAA; 200];
        let mut data = eth_ipv6_hbh_udp([1; 16], [2; 16], &payload);
        let origlen = data.len() as u32;
        // truncate_payload is private; exercise it through `apply`.
        let opts = TransformOptions {
            max_payload_bytes: Some(10),
            ..Default::default()
        };
        let original_hbh = data[14 + 40..14 + 48].to_vec();
        apply(&mut data, 0, 0, origlen, &opts);
        // Ethernet(14) + IPv6(40) + HBH(8) + UDP(8) + 10 = 80
        assert_eq!(data.len(), 80);
        // HBH header bytes must be preserved verbatim.
        assert_eq!(&data[14 + 40..14 + 48], &original_hbh[..]);
        // UDP destination port must still be 200.
        let dport = u16::from_be_bytes([data[14 + 48 + 2], data[14 + 48 + 3]]);
        assert_eq!(dport, 200);
    }

    #[test]
    fn test_reframe_v4_to_v6_rejects_malformed_ihl() {
        // Build a valid v4/UDP frame then poke an invalid IHL (= 4 → 16 bytes,
        // less than the minimum 20). The reframe must refuse rather than
        // slicing transport bytes from inside the IP header.
        let mut data = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 100, 200, b"x");
        data[14] = 0x44; // version=4, IHL=4 (illegal)
        let mapping = parse_ip_mapping("10.0.0.1=::1").unwrap();
        let mapping2 = parse_ip_mapping("10.0.0.2=::2").unwrap();
        let before = data.clone();
        let _ = apply_ip_map(&mut data, &[mapping, mapping2]);
        // Reframe refused → packet bytes unchanged.
        assert_eq!(data, before);
    }

    #[test]
    fn test_truncate_caps_max_bytes_at_ipv4_total_length() {
        // Passing a huge max_payload_bytes must not silently wrap the
        // IPv4 total-length u16. The truncator should clamp to the field's
        // maximum (65535 minus the headers).
        let payload = vec![0xAA; 100_000];
        let mut data = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &payload);
        let origlen = data.len() as u32;
        let opts = TransformOptions {
            max_payload_bytes: Some(80_000), // larger than u16::MAX
            ..Default::default()
        };
        apply(&mut data, 0, 0, origlen, &opts);
        // Read back the IP total-length field — must equal data.len() - 14.
        let ip_total = u16::from_be_bytes([data[16], data[17]]);
        assert_eq!(ip_total as usize, data.len() - 14);
        // Sanity: data must have been truncated to <= ETH(14) + 65535.
        assert!(data.len() <= 14 + u16::MAX as usize);
    }

    #[test]
    fn test_reframe_v6_to_v4_refuses_packets_with_ext_headers() {
        // Cross-family reframe must not copy ext-header bytes verbatim into
        // an IPv4 packet — the rewritten `protocol` field would be wrong.
        let src_v6 = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let dst_v6 = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        let mut data = eth_ipv6_hbh_udp(src_v6, dst_v6, b"hi");
        let mapping = parse_ip_mapping("fe80::1=10.0.0.1").unwrap();
        let mapping2 = parse_ip_mapping("fe80::2=10.0.0.2").unwrap();
        let before = data.clone();
        let _ = apply_ip_map(&mut data, &[mapping, mapping2]);
        // Bytes must be unchanged: reframe is refused, so apply_ip_map should
        // leave the packet as-is (cross-family path only succeeds via reframe).
        assert_eq!(data, before);
    }
}
