//! Structured packet filter.
//!
//! Filters are evaluated per-packet. Rules within the same category are
//! OR-ed; rules of different categories are AND-ed. An empty [`Filter`]
//! (the default) matches every packet.
//!
//! # Evaluation order
//!
//! 1. Time range (cheapest — no parsing required)
//! 2. Packet length
//! 3. Protocol, IP, port, flow ID, TCP flags (requires etherparse)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use thiserror::Error;

use crate::flow::{FlowKey, normalize_ip};

// ── Error ────────────────────────────────────────────────────────────────────

/// Error type for filter construction.
#[derive(Debug, Error)]
pub enum FilterError {
    #[error("invalid IP address or CIDR: '{0}'")]
    InvalidIp(String),

    #[error("invalid port or range (expected e.g. '443' or '1024-65535'): '{0}'")]
    InvalidPort(String),

    #[error("invalid protocol (expected 'tcp', 'udp', 'icmp', 'icmp6', or a number 0-255): '{0}'")]
    InvalidProto(String),

    #[error("invalid flow ID (expected hex, optionally prefixed with '0x'): '{0}'")]
    InvalidFlowId(String),

    #[error("invalid datetime (expected RFC 3339 or millisecond epoch integer): '{0}'")]
    InvalidDateTime(String),

    #[error(
        "invalid TCP flags (e.g. 'SYN', 'SYN+ACK', 'FIN:exact'); \
         known flags: FIN SYN RST PSH ACK URG ECE CWR: '{0}'"
    )]
    InvalidTcpFlags(String),
}

// ── IpNet ────────────────────────────────────────────────────────────────────

/// An IP network in CIDR notation, or a single host address (`/32` or `/128`).
///
/// IPv4-mapped IPv6 addresses are normalised to IPv4 at parse time so that
/// `::ffff:10.0.0.0/8` and `10.0.0.0/8` behave identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNet {
    V4 { addr: Ipv4Addr, prefix_len: u8 },
    V6 { addr: Ipv6Addr, prefix_len: u8 },
}

impl IpNet {
    /// Parse an address or CIDR prefix string.
    ///
    /// # Errors
    /// Returns [`FilterError::InvalidIp`] if the string cannot be parsed.
    pub fn parse(s: &str) -> Result<Self, FilterError> {
        let err = || FilterError::InvalidIp(s.to_owned());

        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let prefix_len: u8 = prefix_str.parse().map_err(|_| err())?;
            let ip = normalize_ip(ip_str.parse::<IpAddr>().map_err(|_| err())?);
            match ip {
                IpAddr::V4(v4) => {
                    if prefix_len > 32 {
                        return Err(err());
                    }
                    Ok(Self::V4 {
                        addr: v4,
                        prefix_len,
                    })
                }
                IpAddr::V6(v6) => {
                    if prefix_len > 128 {
                        return Err(err());
                    }
                    Ok(Self::V6 {
                        addr: v6,
                        prefix_len,
                    })
                }
            }
        } else {
            match normalize_ip(s.parse::<IpAddr>().map_err(|_| err())?) {
                IpAddr::V4(v4) => Ok(Self::V4 {
                    addr: v4,
                    prefix_len: 32,
                }),
                IpAddr::V6(v6) => Ok(Self::V6 {
                    addr: v6,
                    prefix_len: 128,
                }),
            }
        }
    }

    /// Return `true` if `ip` falls within this network.
    ///
    /// An IPv4 network and an IPv6 network never overlap. The `ip` argument
    /// is normalised before comparison so that IPv4-mapped addresses match
    /// their IPv4 equivalents.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        match (self, ip) {
            (Self::V4 { addr, prefix_len }, IpAddr::V4(v4)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let shift = 32 - u32::from(*prefix_len);
                (u32::from(*addr) >> shift) == (u32::from(v4) >> shift)
            }
            (Self::V6 { addr, prefix_len }, IpAddr::V6(v6)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let shift = 128 - u128::from(*prefix_len);
                (u128::from(*addr) >> shift) == (u128::from(v6) >> shift)
            }
            _ => false,
        }
    }
}

// ── PortRange ────────────────────────────────────────────────────────────────

/// A single port or an inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// Parse `"443"` or `"1024-65535"`.
    ///
    /// # Errors
    /// Returns [`FilterError::InvalidPort`] if the string cannot be parsed or
    /// `start > end`.
    pub fn parse(s: &str) -> Result<Self, FilterError> {
        let err = || FilterError::InvalidPort(s.to_owned());
        if let Some((lo, hi)) = s.split_once('-') {
            let start: u16 = lo.trim().parse().map_err(|_| err())?;
            let end: u16 = hi.trim().parse().map_err(|_| err())?;
            if start > end {
                return Err(err());
            }
            Ok(Self { start, end })
        } else {
            let p: u16 = s.trim().parse().map_err(|_| err())?;
            Ok(Self { start: p, end: p })
        }
    }

    /// Return `true` if `port` is within `[start, end]`.
    pub fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

// ── TcpFlagsFilter ───────────────────────────────────────────────────────────

/// TCP control-flags filter.
///
/// The `mask` field selects which bits are tested; `value` is the expected
/// result of `flags & mask`.
///
/// - **any mode** (default): at least one bit in `mask` must be set —
///   `(flags & mask) != 0`.
/// - **exact mode** (append `:exact` to the flag string): all bits in `mask`
///   must equal `value` — `(flags & mask) == value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlagsFilter {
    /// Bitmask of flags to test.
    pub mask: u8,
    /// Expected value under `mask` (used in exact mode).
    pub value: u8,
    /// When `true`, require `(flags & mask) == value`; otherwise `!= 0`.
    pub exact: bool,
}

impl TcpFlagsFilter {
    /// Parse a flag specification string.
    ///
    /// Flags are joined with `+`: `"SYN"`, `"SYN+ACK"`, `"RST+FIN"`.
    /// Append `:exact` for exact-match mode (default: any).
    ///
    /// Known flag names (case-insensitive): `FIN`, `SYN`, `RST`, `PSH`,
    /// `ACK`, `URG`, `ECE`, `CWR`.
    ///
    /// # Errors
    /// Returns [`FilterError::InvalidTcpFlags`] for unknown names or an
    /// empty specification.
    pub fn parse(s: &str) -> Result<Self, FilterError> {
        let err = || FilterError::InvalidTcpFlags(s.to_owned());

        let (flags_part, exact) = if let Some(f) = s.strip_suffix(":exact") {
            (f, true)
        } else if let Some(f) = s.strip_suffix(":any") {
            (f, false)
        } else {
            (s, false)
        };

        let mut mask = 0u8;
        for token in flags_part.split('+') {
            let bit = match token.trim().to_ascii_uppercase().as_str() {
                "FIN" => 0x01,
                "SYN" => 0x02,
                "RST" => 0x04,
                "PSH" => 0x08,
                "ACK" => 0x10,
                "URG" => 0x20,
                "ECE" => 0x40,
                "CWR" => 0x80,
                _ => return Err(err()),
            };
            mask |= bit;
        }
        if mask == 0 {
            return Err(err());
        }
        Ok(Self {
            mask,
            value: mask,
            exact,
        })
    }

    /// Return `true` if `flags` satisfies this filter.
    pub fn matches(self, flags: u8) -> bool {
        if self.exact {
            // All specified flags must be set and no other flags may be set.
            flags == self.value
        } else {
            (flags & self.mask) != 0
        }
    }
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Parse a comma-separated protocol list into IP protocol numbers.
///
/// Accepts well-known names (`tcp`, `udp`, `icmp`, `icmp6`) or decimal
/// numbers `0–255`.
///
/// # Errors
/// Returns [`FilterError::InvalidProto`] for any unrecognised token.
pub fn parse_proto_list(s: &str) -> Result<Vec<u8>, FilterError> {
    s.split(',').map(|p| parse_proto(p.trim())).collect()
}

fn parse_proto(s: &str) -> Result<u8, FilterError> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmp6" | "icmpv6" => Ok(58),
        "sctp" => Ok(132),
        "esp" => Ok(50),
        "ah" => Ok(51),
        other => other
            .parse::<u8>()
            .map_err(|_| FilterError::InvalidProto(s.to_owned())),
    }
}

/// Parse a comma-separated list of hex flow IDs.
///
/// Each entry may be prefixed with `0x`.
///
/// # Errors
/// Returns [`FilterError::InvalidFlowId`] for any non-hex token.
pub fn parse_flow_ids(s: &str) -> Result<Vec<u64>, FilterError> {
    s.split(',')
        .map(|id| {
            let id = id.trim().trim_start_matches("0x");
            u64::from_str_radix(id, 16).map_err(|_| FilterError::InvalidFlowId(id.to_owned()))
        })
        .collect()
}

/// Parse an RFC 3339 datetime string or a millisecond-epoch integer to
/// nanoseconds since the Unix epoch.
///
/// # Errors
/// Returns [`FilterError::InvalidDateTime`] if the string is neither a valid
/// RFC 3339 string nor a decimal integer.
pub fn parse_datetime_ns(s: &str) -> Result<u64, FilterError> {
    // Try ms epoch integer first.
    if let Ok(ms) = s.parse::<u64>() {
        return Ok(ms.saturating_mul(1_000_000));
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|_| FilterError::InvalidDateTime(s.to_owned()))
        .and_then(|dt| {
            let ns = dt
                .timestamp_nanos_opt()
                .ok_or_else(|| FilterError::InvalidDateTime(s.to_owned()))?;
            Ok(ns.max(0) as u64)
        })
}

// ── PacketMeta ───────────────────────────────────────────────────────────────

/// Packet metadata extracted for filter evaluation.
///
/// `flow_key` is `None` for non-IP frames (e.g. ARP). `tcp_flags` is `0`
/// for non-TCP traffic.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    /// Packet timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Number of captured bytes (without the record header).
    pub captured_len: u32,
    /// Parsed 5-tuple; `None` for non-IP or unrecognised frames.
    pub flow_key: Option<FlowKey>,
    /// TCP control flags; `0` when the transport is not TCP.
    pub tcp_flags: u8,
}

impl PacketMeta {
    /// Extract filter-relevant metadata from a raw Ethernet frame.
    pub fn from_packet(timestamp_ns: u64, captured_len: u32, data: &[u8]) -> Self {
        let (flow_key, tcp_flags) = parse_ethernet(data);
        Self {
            timestamp_ns,
            captured_len,
            flow_key,
            tcp_flags,
        }
    }
}

fn parse_ethernet(data: &[u8]) -> (Option<FlowKey>, u8) {
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s) => s,
        Err(_) => return (None, 0),
    };

    let (src_ip, dst_ip, protocol) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                h.protocol().0,
            )
        }
        Some(NetSlice::Ipv6(v6)) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                h.next_header().0,
            )
        }
        _ => return (None, 0),
    };

    let (src_port, dst_port, tcp_flags) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let mut f = 0u8;
            if tcp.fin() {
                f |= 0x01;
            }
            if tcp.syn() {
                f |= 0x02;
            }
            if tcp.rst() {
                f |= 0x04;
            }
            if tcp.psh() {
                f |= 0x08;
            }
            if tcp.ack() {
                f |= 0x10;
            }
            if tcp.urg() {
                f |= 0x20;
            }
            if tcp.ece() {
                f |= 0x40;
            }
            if tcp.cwr() {
                f |= 0x80;
            }
            (tcp.source_port(), tcp.destination_port(), f)
        }
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port(), 0),
        _ => (0, 0, 0),
    };

    let key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol);
    (Some(key), tcp_flags)
}

// ── Filter ───────────────────────────────────────────────────────────────────

/// Compiled structured packet filter.
///
/// ## Composition rules
///
/// - Multiple values within the same category are **OR**-ed:
///   two `src_ips` entries keep packets matching **either** network.
/// - Values across different categories are **AND**-ed:
///   a packet must satisfy the protocol filter **and** the IP filter **and**
///   the port filter, etc.
/// - An empty category (zero values / `None`) places no constraint.
///
/// Filters are evaluated during the **second pass** of the sort pipeline,
/// after chronological sorting, before output.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// IP protocol numbers to match. Empty = any protocol.
    pub protocols: Vec<u8>,

    /// Source IP/CIDR rules (OR-ed within this set).
    pub src_ips: Vec<IpNet>,
    /// Destination IP/CIDR rules (OR-ed).
    pub dst_ips: Vec<IpNet>,
    /// Either-endpoint IP/CIDR rules: matches if src **or** dst is in range.
    pub ips: Vec<IpNet>,

    /// Source port ranges (OR-ed). Only applied to TCP/UDP.
    pub src_ports: Vec<PortRange>,
    /// Destination port ranges (OR-ed). Only applied to TCP/UDP.
    pub dst_ports: Vec<PortRange>,
    /// Either-endpoint port ranges: matches if src port **or** dst port is in range.
    pub ports: Vec<PortRange>,

    /// Flow IDs (pre-computed) to retain. Empty = any flow.
    pub flow_ids: Vec<u64>,

    /// Inclusive lower timestamp bound (nanoseconds). `None` = no lower bound.
    pub from_ns: Option<u64>,
    /// Inclusive upper timestamp bound (nanoseconds). `None` = no upper bound.
    pub to_ns: Option<u64>,

    /// TCP control-flags filter.
    pub tcp_flags: Option<TcpFlagsFilter>,

    /// Minimum captured length in bytes. `None` = no minimum.
    pub min_len: Option<u32>,
    /// Maximum captured length in bytes. `None` = no maximum.
    pub max_len: Option<u32>,

    /// When `true`, flow IDs are computed unidirectionally.
    pub unidirectional: bool,
}

impl Filter {
    /// Return `true` if no constraints are set (matches every packet).
    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
            && self.src_ips.is_empty()
            && self.dst_ips.is_empty()
            && self.ips.is_empty()
            && self.src_ports.is_empty()
            && self.dst_ports.is_empty()
            && self.ports.is_empty()
            && self.flow_ids.is_empty()
            && self.from_ns.is_none()
            && self.to_ns.is_none()
            && self.tcp_flags.is_none()
            && self.min_len.is_none()
            && self.max_len.is_none()
    }

    /// Evaluate the filter against `meta`.
    ///
    /// Returns `true` if the packet passes all active constraints.
    pub fn matches(&self, meta: &PacketMeta) -> bool {
        // ── Time range (no parsing needed) ───────────────────────────────────
        if let Some(from) = self.from_ns
            && meta.timestamp_ns < from
        {
            return false;
        }
        if let Some(to) = self.to_ns
            && meta.timestamp_ns > to
        {
            return false;
        }

        // ── Packet length ────────────────────────────────────────────────────
        if let Some(min) = self.min_len
            && meta.captured_len < min
        {
            return false;
        }
        if let Some(max) = self.max_len
            && meta.captured_len > max
        {
            return false;
        }

        // Early exit: remaining checks all require a flow key.
        let need_flow = !self.protocols.is_empty()
            || !self.src_ips.is_empty()
            || !self.dst_ips.is_empty()
            || !self.ips.is_empty()
            || !self.src_ports.is_empty()
            || !self.dst_ports.is_empty()
            || !self.ports.is_empty()
            || !self.flow_ids.is_empty()
            || self.tcp_flags.is_some();

        if !need_flow {
            return true;
        }

        // Non-IP packets fail any flow-level filter.
        let key = match &meta.flow_key {
            Some(k) => k,
            None => return false,
        };

        // ── Protocol ─────────────────────────────────────────────────────────
        if !self.protocols.is_empty() && !self.protocols.contains(&key.protocol) {
            return false;
        }

        // ── IP address / CIDR ────────────────────────────────────────────────
        if !self.src_ips.is_empty() && !self.src_ips.iter().any(|n| n.contains(key.src_ip)) {
            return false;
        }
        if !self.dst_ips.is_empty() && !self.dst_ips.iter().any(|n| n.contains(key.dst_ip)) {
            return false;
        }
        if !self.ips.is_empty()
            && !self
                .ips
                .iter()
                .any(|n| n.contains(key.src_ip) || n.contains(key.dst_ip))
        {
            return false;
        }

        // ── Port (TCP / UDP only; silently ignored for other protocols) ───────
        if matches!(key.protocol, 6 | 17) {
            if !self.src_ports.is_empty()
                && !self.src_ports.iter().any(|r| r.contains(key.src_port))
            {
                return false;
            }
            if !self.dst_ports.is_empty()
                && !self.dst_ports.iter().any(|r| r.contains(key.dst_port))
            {
                return false;
            }
            if !self.ports.is_empty()
                && !self
                    .ports
                    .iter()
                    .any(|r| r.contains(key.src_port) || r.contains(key.dst_port))
            {
                return false;
            }
        }

        // ── Flow ID ──────────────────────────────────────────────────────────
        if !self.flow_ids.is_empty() {
            let id = key.flow_id(self.unidirectional);
            if !self.flow_ids.contains(&id) {
                return false;
            }
        }

        // ── TCP flags (protocol 6 only) ───────────────────────────────────────
        if let Some(flags_filter) = self.tcp_flags
            && key.protocol == 6
            && !flags_filter.matches(meta.tcp_flags)
        {
            return false;
        }

        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn meta(
        ts_ns: u64,
        caplen: u32,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        proto: u8,
        tcp_flags: u8,
    ) -> PacketMeta {
        PacketMeta {
            timestamp_ns: ts_ns,
            captured_len: caplen,
            flow_key: Some(FlowKey::new(src, dst, sport, dport, proto)),
            tcp_flags,
        }
    }

    fn no_flow_meta(ts_ns: u64, caplen: u32) -> PacketMeta {
        PacketMeta {
            timestamp_ns: ts_ns,
            captured_len: caplen,
            flow_key: None,
            tcp_flags: 0,
        }
    }

    // ── IpNet ────────────────────────────────────────────────────────────────

    #[test]
    fn test_ipnet_parse_host_v4() {
        let net = IpNet::parse("10.0.0.1").unwrap();
        assert!(net.contains(v4(10, 0, 0, 1)));
        assert!(!net.contains(v4(10, 0, 0, 2)));
    }

    #[test]
    fn test_ipnet_parse_cidr_v4() {
        let net = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(net.contains(v4(10, 0, 0, 1)));
        assert!(net.contains(v4(10, 255, 255, 255)));
        assert!(!net.contains(v4(11, 0, 0, 1)));
    }

    #[test]
    fn test_ipnet_parse_cidr_v4_slash_32() {
        let net = IpNet::parse("192.168.1.1/32").unwrap();
        assert!(net.contains(v4(192, 168, 1, 1)));
        assert!(!net.contains(v4(192, 168, 1, 2)));
    }

    #[test]
    fn test_ipnet_parse_cidr_v6() {
        let net = IpNet::parse("2001:db8::/32").unwrap();
        assert!(net.contains("2001:db8::1".parse().unwrap()));
        assert!(!net.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_v4_mapped_normalised() {
        // normalize_ip() converts ::ffff:a.b.c.d → plain IPv4 before the CIDR
        // check, so an IPv4 network matches IPv4-mapped IPv6 addresses.
        let net = IpNet::parse("10.0.0.0/8").unwrap();
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(net.contains(mapped));
        let other_mapped: IpAddr = "::ffff:11.0.0.1".parse().unwrap();
        assert!(!net.contains(other_mapped));
    }

    #[test]
    fn test_ipnet_parse_invalid() {
        assert!(IpNet::parse("not-an-ip").is_err());
        assert!(IpNet::parse("10.0.0.0/33").is_err());
        assert!(IpNet::parse("2001:db8::/129").is_err());
    }

    // ── PortRange ────────────────────────────────────────────────────────────

    #[test]
    fn test_port_range_single() {
        let r = PortRange::parse("443").unwrap();
        assert!(r.contains(443));
        assert!(!r.contains(444));
    }

    #[test]
    fn test_port_range_range() {
        let r = PortRange::parse("1024-65535").unwrap();
        assert!(r.contains(1024));
        assert!(r.contains(65535));
        assert!(!r.contains(1023));
    }

    #[test]
    fn test_port_range_invalid() {
        assert!(PortRange::parse("abc").is_err());
        assert!(PortRange::parse("100-50").is_err()); // start > end
    }

    // ── TcpFlagsFilter ───────────────────────────────────────────────────────

    #[test]
    fn test_tcp_flags_syn_any() {
        let f = TcpFlagsFilter::parse("SYN").unwrap();
        assert!(f.matches(0x02)); // SYN set
        assert!(f.matches(0x12)); // SYN+ACK
        assert!(!f.matches(0x10)); // ACK only
    }

    #[test]
    fn test_tcp_flags_syn_ack_exact() {
        let f = TcpFlagsFilter::parse("SYN+ACK:exact").unwrap();
        assert!(f.matches(0x12)); // SYN+ACK exactly
        assert!(!f.matches(0x02)); // SYN only
        assert!(!f.matches(0x13)); // SYN+ACK+FIN
    }

    #[test]
    fn test_tcp_flags_invalid() {
        assert!(TcpFlagsFilter::parse("").is_err());
        assert!(TcpFlagsFilter::parse("INVALID").is_err());
    }

    // ── parse_proto_list ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_proto_list() {
        assert_eq!(parse_proto_list("tcp,udp").unwrap(), [6, 17]);
        assert_eq!(parse_proto_list("icmp").unwrap(), [1]);
        assert_eq!(parse_proto_list("6,17").unwrap(), [6, 17]);
        assert!(parse_proto_list("foobar").is_err());
    }

    // ── parse_flow_ids ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_flow_ids() {
        assert_eq!(parse_flow_ids("deadbeef").unwrap(), [0xdeadbeefu64]);
        assert_eq!(
            parse_flow_ids("0xdeadbeef,0xcafe1234").unwrap(),
            [0xdeadbeefu64, 0xcafe1234u64]
        );
        assert!(parse_flow_ids("xyz").is_err());
    }

    // ── parse_datetime_ns ────────────────────────────────────────────────────

    #[test]
    fn test_parse_datetime_ms_epoch() {
        assert_eq!(parse_datetime_ns("1000").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_datetime_rfc3339() {
        let ns = parse_datetime_ns("1970-01-01T00:00:01Z").unwrap();
        assert_eq!(ns, 1_000_000_000);
    }

    #[test]
    fn test_parse_datetime_invalid() {
        assert!(parse_datetime_ns("not-a-date").is_err());
    }

    // ── Filter::matches ──────────────────────────────────────────────────────

    #[test]
    fn test_empty_filter_matches_everything() {
        let f = Filter::default();
        assert!(f.is_empty());
        assert!(f.matches(&meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 80, 443, 6, 0)));
        assert!(f.matches(&no_flow_meta(0, 100)));
    }

    #[test]
    fn test_filter_time_range() {
        let mut f = Filter::default();
        f.from_ns = Some(1_000);
        f.to_ns = Some(2_000);
        assert!(f.matches(&no_flow_meta(1_000, 10)));
        assert!(f.matches(&no_flow_meta(2_000, 10)));
        assert!(!f.matches(&no_flow_meta(999, 10)));
        assert!(!f.matches(&no_flow_meta(2_001, 10)));
    }

    #[test]
    fn test_filter_packet_length() {
        let mut f = Filter::default();
        f.min_len = Some(50);
        f.max_len = Some(100);
        assert!(f.matches(&no_flow_meta(0, 50)));
        assert!(f.matches(&no_flow_meta(0, 100)));
        assert!(!f.matches(&no_flow_meta(0, 49)));
        assert!(!f.matches(&no_flow_meta(0, 101)));
    }

    #[test]
    fn test_filter_protocol_tcp_only() {
        let mut f = Filter::default();
        f.protocols = vec![6]; // TCP
        let tcp = meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 80, 6, 0);
        let udp = meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 53, 17, 0);
        assert!(f.matches(&tcp));
        assert!(!f.matches(&udp));
    }

    #[test]
    fn test_filter_protocol_multiple_or() {
        let mut f = Filter::default();
        f.protocols = vec![6, 17]; // TCP or UDP
        assert!(f.matches(&meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, 6, 0)));
        assert!(f.matches(&meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, 17, 0)));
        assert!(!f.matches(&meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 1, 0))); // ICMP
    }

    #[test]
    fn test_filter_src_ip_cidr() {
        let mut f = Filter::default();
        f.src_ips = vec![IpNet::parse("10.0.0.0/8").unwrap()];
        assert!(f.matches(&meta(0, 60, v4(10, 1, 2, 3), v4(8, 8, 8, 8), 0, 0, 17, 0)));
        assert!(!f.matches(&meta(0, 60, v4(11, 0, 0, 1), v4(8, 8, 8, 8), 0, 0, 17, 0)));
    }

    #[test]
    fn test_filter_dst_ip() {
        let mut f = Filter::default();
        f.dst_ips = vec![IpNet::parse("8.8.8.8").unwrap()];
        assert!(f.matches(&meta(0, 60, v4(1, 2, 3, 4), v4(8, 8, 8, 8), 0, 0, 17, 0)));
        assert!(!f.matches(&meta(0, 60, v4(1, 2, 3, 4), v4(1, 1, 1, 1), 0, 0, 17, 0)));
    }

    #[test]
    fn test_filter_ip_either_endpoint() {
        let mut f = Filter::default();
        f.ips = vec![IpNet::parse("10.0.0.1").unwrap()];
        // Matches if src OR dst is 10.0.0.1
        assert!(f.matches(&meta(0, 60, v4(10, 0, 0, 1), v4(8, 8, 8, 8), 0, 0, 17, 0)));
        assert!(f.matches(&meta(0, 60, v4(8, 8, 8, 8), v4(10, 0, 0, 1), 0, 0, 17, 0)));
        assert!(!f.matches(&meta(0, 60, v4(1, 2, 3, 4), v4(5, 6, 7, 8), 0, 0, 17, 0)));
    }

    #[test]
    fn test_filter_src_ip_multiple_or() {
        let mut f = Filter::default();
        f.src_ips = vec![
            IpNet::parse("10.0.0.1").unwrap(),
            IpNet::parse("192.168.0.0/16").unwrap(),
        ];
        assert!(f.matches(&meta(0, 60, v4(10, 0, 0, 1), v4(8, 8, 8, 8), 0, 0, 6, 0)));
        assert!(f.matches(&meta(0, 60, v4(192, 168, 1, 2), v4(8, 8, 8, 8), 0, 0, 6, 0)));
        assert!(!f.matches(&meta(0, 60, v4(172, 16, 0, 1), v4(8, 8, 8, 8), 0, 0, 6, 0)));
    }

    #[test]
    fn test_filter_dst_port() {
        let mut f = Filter::default();
        f.dst_ports = vec![PortRange {
            start: 443,
            end: 443,
        }];
        assert!(f.matches(&meta(
            0,
            60,
            v4(1, 1, 1, 1),
            v4(2, 2, 2, 2),
            1234,
            443,
            6,
            0
        )));
        assert!(!f.matches(&meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 80, 6, 0)));
    }

    #[test]
    fn test_filter_port_range_either() {
        let mut f = Filter::default();
        f.ports = vec![PortRange {
            start: 8000,
            end: 9000,
        }];
        assert!(f.matches(&meta(
            0,
            60,
            v4(1, 1, 1, 1),
            v4(2, 2, 2, 2),
            8080,
            1234,
            6,
            0
        )));
        assert!(f.matches(&meta(
            0,
            60,
            v4(1, 1, 1, 1),
            v4(2, 2, 2, 2),
            1234,
            8080,
            6,
            0
        )));
        assert!(!f.matches(&meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 80, 443, 6, 0)));
    }

    #[test]
    fn test_filter_port_ignored_for_icmp() {
        // Port filters are silently ignored for non-TCP/UDP protocols.
        let mut f = Filter::default();
        f.dst_ports = vec![PortRange {
            start: 443,
            end: 443,
        }];
        // ICMP packet with dst_port=0: port filter is ignored, but protocol
        // filter is not set, so the only active filter is dst_port which
        // doesn't apply to ICMP → packet should pass.
        assert!(f.matches(&meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 1, 0)));
    }

    #[test]
    fn test_filter_flow_id() {
        let key = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1234, 443, 6);
        let id = key.flow_id(false);
        let mut f = Filter::default();
        f.flow_ids = vec![id];

        let matching = PacketMeta {
            timestamp_ns: 0,
            captured_len: 60,
            flow_key: Some(key),
            tcp_flags: 0,
        };
        assert!(f.matches(&matching));

        let other = PacketMeta {
            timestamp_ns: 0,
            captured_len: 60,
            flow_key: Some(FlowKey::new(v4(10, 0, 0, 3), v4(10, 0, 0, 4), 5678, 80, 6)),
            tcp_flags: 0,
        };
        assert!(!f.matches(&other));
    }

    #[test]
    fn test_filter_tcp_flags() {
        let mut f = Filter::default();
        f.tcp_flags = Some(TcpFlagsFilter::parse("SYN").unwrap());

        // SYN packet
        assert!(f.matches(&meta(
            0,
            60,
            v4(1, 1, 1, 1),
            v4(2, 2, 2, 2),
            1234,
            80,
            6,
            0x02
        )));
        // ACK-only packet
        assert!(!f.matches(&meta(
            0,
            60,
            v4(1, 1, 1, 1),
            v4(2, 2, 2, 2),
            1234,
            80,
            6,
            0x10
        )));
    }

    #[test]
    fn test_filter_and_composition() {
        // Protocol=TCP AND dst_port=443 AND src_ip=10.0.0.0/8 — all must hold.
        let mut f = Filter::default();
        f.protocols = vec![6];
        f.dst_ports = vec![PortRange {
            start: 443,
            end: 443,
        }];
        f.src_ips = vec![IpNet::parse("10.0.0.0/8").unwrap()];

        // All match
        assert!(f.matches(&meta(
            0,
            60,
            v4(10, 1, 2, 3),
            v4(8, 8, 8, 8),
            5000,
            443,
            6,
            0
        )));
        // Wrong protocol
        assert!(!f.matches(&meta(
            0,
            60,
            v4(10, 1, 2, 3),
            v4(8, 8, 8, 8),
            5000,
            443,
            17,
            0
        )));
        // Wrong dst port
        assert!(!f.matches(&meta(
            0,
            60,
            v4(10, 1, 2, 3),
            v4(8, 8, 8, 8),
            5000,
            80,
            6,
            0
        )));
        // Wrong src IP
        assert!(!f.matches(&meta(
            0,
            60,
            v4(11, 0, 0, 1),
            v4(8, 8, 8, 8),
            5000,
            443,
            6,
            0
        )));
    }

    #[test]
    fn test_filter_non_ip_fails_when_flow_filter_active() {
        let mut f = Filter::default();
        f.protocols = vec![6];
        assert!(!f.matches(&no_flow_meta(0, 100)));
    }

    #[test]
    fn test_filter_non_ip_passes_when_only_length_filter() {
        let mut f = Filter::default();
        f.min_len = Some(50);
        assert!(f.matches(&no_flow_meta(0, 60)));
        assert!(!f.matches(&no_flow_meta(0, 40)));
    }
}
