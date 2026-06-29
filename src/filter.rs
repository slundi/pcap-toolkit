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

use rustc_hash::FxHashSet;

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

    #[error("invalid datetime (expected RFC 3339 or Unix epoch integer in seconds): '{0}'")]
    InvalidDateTime(String),

    #[error(
        "invalid TCP flags (e.g. 'SYN', 'SYN+ACK', 'FIN:exact'); \
         known flags: FIN SYN RST PSH ACK URG ECE CWR: '{0}'"
    )]
    InvalidTcpFlags(String),

    #[error("invalid filter operator (expected 'and', 'or', or 'not'): '{0}'")]
    InvalidOp(String),

    #[error("invalid range: {field} lower bound {lo} is greater than upper bound {hi}")]
    InvalidRange {
        field: &'static str,
        lo: u64,
        hi: u64,
    },
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
            (flags & self.mask) == self.value
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

/// Parse an RFC 3339 datetime string or a Unix epoch integer (in **seconds**)
/// to nanoseconds since the Unix epoch.
///
/// Bare integers are treated as whole seconds, which is the dominant convention
/// (`date +%s`, Python `time.time()`, etc.). Sub-second precision requires an
/// RFC 3339 string with a fractional seconds component.
///
/// # Errors
/// Returns [`FilterError::InvalidDateTime`] if the string is neither a valid
/// RFC 3339 string nor a decimal integer.
pub fn parse_datetime_ns(s: &str) -> Result<u64, FilterError> {
    // Bare integers are Unix epoch seconds (the dominant convention).
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(secs.saturating_mul(1_000_000_000));
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

// ── Logical composition ───────────────────────────────────────────────────────

/// Logical operator used when chaining [`FilterRule`]s in a [`Filter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Op {
    /// `accumulated = accumulated AND rule.matches(packet)` (default).
    #[default]
    And,
    /// `accumulated = accumulated OR rule.matches(packet)`.
    Or,
    /// `accumulated = accumulated AND NOT rule.matches(packet)`.
    Not,
}

impl Op {
    /// Parse `"and"`, `"or"`, or `"not"` (case-insensitive).
    ///
    /// # Errors
    /// Returns [`FilterError::InvalidOp`] for any other value.
    pub fn parse(s: &str) -> Result<Self, FilterError> {
        match s.to_ascii_lowercase().as_str() {
            "and" => Ok(Self::And),
            "or" => Ok(Self::Or),
            "not" => Ok(Self::Not),
            _ => Err(FilterError::InvalidOp(s.to_owned())),
        }
    }
}

// ── Shared flat-body matching ─────────────────────────────────────────────────

/// Private trait — provides getters so `eval_body` can work over both
/// [`Filter`] (base body) and [`FilterRule`] without code duplication.
trait FilterBody {
    fn protocols(&self) -> &[u8];
    fn src_ips(&self) -> &[IpNet];
    fn dst_ips(&self) -> &[IpNet];
    fn ips(&self) -> &[IpNet];
    fn src_ports(&self) -> &[PortRange];
    fn dst_ports(&self) -> &[PortRange];
    fn ports(&self) -> &[PortRange];
    fn flow_ids(&self) -> &FxHashSet<u64>;
    fn start_ns(&self) -> Option<u64>;
    fn end_ns(&self) -> Option<u64>;
    fn tcp_flags(&self) -> Option<TcpFlagsFilter>;
    fn min_len(&self) -> Option<u32>;
    fn max_len(&self) -> Option<u32>;
    fn unidirectional(&self) -> bool;
}

/// Generate a `FilterBody` impl for a struct whose fields have the same names.
macro_rules! impl_filter_body {
    ($T:ty) => {
        impl FilterBody for $T {
            fn protocols(&self) -> &[u8] {
                &self.protocols
            }
            fn src_ips(&self) -> &[IpNet] {
                &self.src_ips
            }
            fn dst_ips(&self) -> &[IpNet] {
                &self.dst_ips
            }
            fn ips(&self) -> &[IpNet] {
                &self.ips
            }
            fn src_ports(&self) -> &[PortRange] {
                &self.src_ports
            }
            fn dst_ports(&self) -> &[PortRange] {
                &self.dst_ports
            }
            fn ports(&self) -> &[PortRange] {
                &self.ports
            }
            fn flow_ids(&self) -> &FxHashSet<u64> {
                &self.flow_ids
            }
            fn start_ns(&self) -> Option<u64> {
                self.from_ns
            }
            fn end_ns(&self) -> Option<u64> {
                self.to_ns
            }
            fn tcp_flags(&self) -> Option<TcpFlagsFilter> {
                self.tcp_flags
            }
            fn min_len(&self) -> Option<u32> {
                self.min_len
            }
            fn max_len(&self) -> Option<u32> {
                self.max_len
            }
            fn unidirectional(&self) -> bool {
                self.unidirectional
            }
        }
    };
}

/// Core flat-filter evaluation shared by [`Filter`] and [`FilterRule`].
///
/// - Categories are **AND**-ed: all active categories must pass.
/// - Values within a category are **OR**-ed: any one match is sufficient.
/// - Port filters are silently skipped for protocols other than TCP (6) / UDP (17).
fn eval_body(b: &impl FilterBody, meta: &PacketMeta) -> bool {
    // ── Time range ────────────────────────────────────────────────────────
    if let Some(from) = b.start_ns()
        && meta.timestamp_ns < from
    {
        return false;
    }
    if let Some(to) = b.end_ns()
        && meta.timestamp_ns > to
    {
        return false;
    }

    // ── Packet length ─────────────────────────────────────────────────────
    if let Some(min) = b.min_len()
        && meta.captured_len < min
    {
        return false;
    }
    if let Some(max) = b.max_len()
        && meta.captured_len > max
    {
        return false;
    }

    // Early exit: remaining checks all require a parsed flow key.
    let need_flow = !b.protocols().is_empty()
        || !b.src_ips().is_empty()
        || !b.dst_ips().is_empty()
        || !b.ips().is_empty()
        || !b.src_ports().is_empty()
        || !b.dst_ports().is_empty()
        || !b.ports().is_empty()
        || !b.flow_ids().is_empty()
        || b.tcp_flags().is_some();

    if !need_flow {
        return true;
    }

    // Non-IP packets fail any flow-level filter.
    let key = match &meta.flow_key {
        Some(k) => k,
        None => return false,
    };

    // ── Protocol ──────────────────────────────────────────────────────────
    if !b.protocols().is_empty() && !b.protocols().contains(&key.protocol) {
        return false;
    }

    // ── IP address / CIDR ─────────────────────────────────────────────────
    if !b.src_ips().is_empty() && !b.src_ips().iter().any(|n| n.contains(key.src_ip)) {
        return false;
    }
    if !b.dst_ips().is_empty() && !b.dst_ips().iter().any(|n| n.contains(key.dst_ip)) {
        return false;
    }
    if !b.ips().is_empty()
        && !b
            .ips()
            .iter()
            .any(|n| n.contains(key.src_ip) || n.contains(key.dst_ip))
    {
        return false;
    }

    // ── Port (TCP / UDP only; silently ignored for other protocols) ────────
    if matches!(key.protocol, 6 | 17) {
        if !b.src_ports().is_empty() && !b.src_ports().iter().any(|r| r.contains(key.src_port)) {
            return false;
        }
        if !b.dst_ports().is_empty() && !b.dst_ports().iter().any(|r| r.contains(key.dst_port)) {
            return false;
        }
        if !b.ports().is_empty()
            && !b
                .ports()
                .iter()
                .any(|r| r.contains(key.src_port) || r.contains(key.dst_port))
        {
            return false;
        }
    }

    // ── Flow ID ───────────────────────────────────────────────────────────
    if !b.flow_ids().is_empty() {
        let id = key.flow_id(b.unidirectional());
        if !b.flow_ids().contains(&id) {
            return false;
        }
    }

    // ── TCP flags (protocol 6 only) ────────────────────────────────────────
    if let Some(ff) = b.tcp_flags()
        && key.protocol == 6
        && !ff.matches(meta.tcp_flags)
    {
        return false;
    }

    true
}

// ── Filter ───────────────────────────────────────────────────────────────────

/// Compiled structured packet filter.
///
/// ## Flat-body composition (within the base filter)
///
/// - Multiple values within the same category are **OR**-ed.
/// - Values across different categories are **AND**-ed.
/// - An empty category places no constraint.
///
/// ## Global negation
///
/// When `negate` is `true` the entire result of the flat-body evaluation
/// (and the rule chain, if any) is inverted.  Use `--not` on the CLI.
///
/// ## Rule chain
///
/// `rules` is an ordered list of [`FilterRule`]s evaluated left-to-right
/// after the base body. Each rule carries an [`Op`] that controls how it
/// combines with the accumulated result:
///
/// - `Op::And` — `acc = acc AND rule.matches(pkt)` (default)
/// - `Op::Or`  — `acc = acc OR rule.matches(pkt)`
/// - `Op::Not` — `acc = acc AND NOT rule.matches(pkt)`
///
/// An empty `rules` list (the default) has no effect.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// When `true`, the entire filter result is inverted.
    pub negate: bool,

    /// Additional rules chained after the base body.
    pub rules: Vec<FilterRule>,

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
    pub flow_ids: FxHashSet<u64>,

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

impl_filter_body!(Filter);

impl Filter {
    /// Return `true` if the filter places no constraints (matches every packet).
    ///
    /// A filter with `negate = true` or a non-empty `rules` list is never empty.
    pub fn is_empty(&self) -> bool {
        !self.negate
            && self.rules.is_empty()
            && self.protocols.is_empty()
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

    /// Check that the filter's range bounds are internally consistent.
    ///
    /// Catches cases that would silently reject every packet, e.g. an
    /// inverted timestamp window (`from_ns > to_ns`) or `min_len > max_len`.
    /// All other fields (sets, optional values) cannot be inconsistent in
    /// themselves and are not checked here.
    ///
    /// # Errors
    /// Returns [`FilterError::InvalidRange`] for the first bad pair found.
    ///
    /// # Examples
    /// ```
    /// use pcap_toolkit::filter::Filter;
    /// let f = Filter {
    ///     from_ns: Some(2_000),
    ///     to_ns: Some(1_000),
    ///     ..Filter::default()
    /// };
    /// assert!(f.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), FilterError> {
        if let (Some(lo), Some(hi)) = (self.from_ns, self.to_ns)
            && lo > hi
        {
            return Err(FilterError::InvalidRange {
                field: "timestamp",
                lo,
                hi,
            });
        }
        if let (Some(lo), Some(hi)) = (self.min_len, self.max_len)
            && lo > hi
        {
            return Err(FilterError::InvalidRange {
                field: "length",
                lo: lo as u64,
                hi: hi as u64,
            });
        }
        for rule in &self.rules {
            if let (Some(lo), Some(hi)) = (rule.from_ns, rule.to_ns)
                && lo > hi
            {
                return Err(FilterError::InvalidRange {
                    field: "rule timestamp",
                    lo,
                    hi,
                });
            }
            if let (Some(lo), Some(hi)) = (rule.min_len, rule.max_len)
                && lo > hi
            {
                return Err(FilterError::InvalidRange {
                    field: "rule length",
                    lo: lo as u64,
                    hi: hi as u64,
                });
            }
        }
        Ok(())
    }

    /// Evaluate the filter against `meta`.
    ///
    /// 1. Evaluate the base flat body.
    /// 2. Apply `negate` to that result.
    /// 3. Fold over `rules` using each rule's [`Op`].
    ///
    /// Returns `true` if the packet passes.
    pub fn matches(&self, meta: &PacketMeta) -> bool {
        let base = eval_body(self, meta);
        let acc = if self.negate { !base } else { base };
        self.rules.iter().fold(acc, |acc, rule| {
            let rule_result = eval_body(rule, meta);
            match rule.op {
                Op::And => acc && rule_result,
                Op::Or => acc || rule_result,
                Op::Not => acc && !rule_result,
            }
        })
    }
}

// ── FilterRule ────────────────────────────────────────────────────────────────

/// A single rule in a [`Filter`] rule chain.
///
/// All flat-body semantics are identical to the base [`Filter`]: categories
/// are OR-ed within, AND-ed across.  The [`Op`] field controls how this rule
/// is combined with the accumulated result.
#[derive(Debug, Default, Clone)]
pub struct FilterRule {
    /// How this rule combines with the accumulated filter result.
    pub op: Op,

    pub protocols: Vec<u8>,
    pub src_ips: Vec<IpNet>,
    pub dst_ips: Vec<IpNet>,
    pub ips: Vec<IpNet>,
    pub src_ports: Vec<PortRange>,
    pub dst_ports: Vec<PortRange>,
    pub ports: Vec<PortRange>,
    pub flow_ids: FxHashSet<u64>,
    pub from_ns: Option<u64>,
    pub to_ns: Option<u64>,
    pub tcp_flags: Option<TcpFlagsFilter>,
    pub min_len: Option<u32>,
    pub max_len: Option<u32>,
    pub unidirectional: bool,
}

impl_filter_body!(FilterRule);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[allow(clippy::too_many_arguments)]
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
        // Exact mode: `(flags & mask) == value` — both SYN and ACK bits must
        // be set; bits outside the mask are ignored.
        let f = TcpFlagsFilter::parse("SYN+ACK:exact").unwrap();
        assert!(f.matches(0x12)); // SYN+ACK
        assert!(f.matches(0x13)); // SYN+ACK+FIN — FIN is outside the mask, still matches
        assert!(f.matches(0x1A)); // SYN+ACK+PSH
        assert!(!f.matches(0x02)); // SYN only — ACK bit missing
        assert!(!f.matches(0x10)); // ACK only — SYN bit missing
        assert!(!f.matches(0x00)); // no flags
    }

    #[test]
    fn test_tcp_flags_syn_exact_alone() {
        // SYN:exact requires the SYN bit to be set; other bits are ignored.
        let f = TcpFlagsFilter::parse("SYN:exact").unwrap();
        assert!(f.matches(0x02)); // SYN
        assert!(f.matches(0x12)); // SYN+ACK
        assert!(!f.matches(0x10)); // ACK only
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

    #[test]
    fn test_parse_proto_list_named_extras() {
        // Less common protocols accepted by name (regression: previously
        // uncovered).
        assert_eq!(parse_proto_list("sctp").unwrap(), [132]);
        assert_eq!(parse_proto_list("esp").unwrap(), [50]);
        assert_eq!(parse_proto_list("ah").unwrap(), [51]);
        assert_eq!(parse_proto_list("icmpv6").unwrap(), [58]);
        assert_eq!(
            parse_proto_list("tcp,sctp,esp,ah").unwrap(),
            [6, 132, 50, 51]
        );
    }

    #[test]
    fn test_tcp_flags_any_suffix_matches_default() {
        // The `:any` suffix is documented but was previously untested.
        // It must behave identically to the bare form: at least one bit set.
        let bare = TcpFlagsFilter::parse("SYN+ACK").unwrap();
        let any = TcpFlagsFilter::parse("SYN+ACK:any").unwrap();
        assert_eq!(bare, any);
        // Matches packets with either flag bit set.
        assert!(any.matches(0x02)); // SYN
        assert!(any.matches(0x10)); // ACK
        assert!(any.matches(0x12)); // SYN+ACK
        assert!(!any.matches(0x04)); // RST only
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
    fn test_parse_datetime_secs_epoch() {
        // "1" second = 1_000_000_000 ns.
        assert_eq!(parse_datetime_ns("1").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_datetime_secs_epoch_common_value() {
        // A realistic Unix timestamp (2001-09-09 01:46:40 UTC).
        let secs: u64 = 1_000_000_000;
        let ns = parse_datetime_ns(&secs.to_string()).unwrap();
        assert_eq!(ns, secs * 1_000_000_000);
    }

    #[test]
    fn test_parse_datetime_secs_matches_rfc3339() {
        // "1" second since epoch via integer must equal the RFC 3339 equivalent.
        let via_int = parse_datetime_ns("1").unwrap();
        let via_rfc = parse_datetime_ns("1970-01-01T00:00:01Z").unwrap();
        assert_eq!(via_int, via_rfc);
    }

    #[test]
    fn test_parse_datetime_zero() {
        assert_eq!(parse_datetime_ns("0").unwrap(), 0);
    }

    #[test]
    fn test_parse_datetime_rfc3339() {
        let ns = parse_datetime_ns("1970-01-01T00:00:01Z").unwrap();
        assert_eq!(ns, 1_000_000_000);
    }

    #[test]
    fn test_parse_datetime_rfc3339_subsecond() {
        // Sub-second precision is only available via RFC 3339.
        let ns = parse_datetime_ns("1970-01-01T00:00:01.5Z").unwrap();
        assert_eq!(ns, 1_500_000_000);
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
        let f = Filter {
            from_ns: Some(1_000),
            to_ns: Some(2_000),
            ..Default::default()
        };
        assert!(f.matches(&no_flow_meta(1_000, 10)));
        assert!(f.matches(&no_flow_meta(2_000, 10)));
        assert!(!f.matches(&no_flow_meta(999, 10)));
        assert!(!f.matches(&no_flow_meta(2_001, 10)));
    }

    #[test]
    fn test_filter_packet_length() {
        let f = Filter {
            min_len: Some(50),
            max_len: Some(100),
            ..Default::default()
        };
        assert!(f.matches(&no_flow_meta(0, 50)));
        assert!(f.matches(&no_flow_meta(0, 100)));
        assert!(!f.matches(&no_flow_meta(0, 49)));
        assert!(!f.matches(&no_flow_meta(0, 101)));
    }

    #[test]
    fn test_filter_protocol_tcp_only() {
        let f = Filter {
            protocols: vec![6], // TCP
            ..Default::default()
        };
        let tcp = meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 80, 6, 0);
        let udp = meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 53, 17, 0);
        assert!(f.matches(&tcp));
        assert!(!f.matches(&udp));
    }

    #[test]
    fn test_filter_protocol_multiple_or() {
        let f = Filter {
            protocols: vec![6, 17], // TCP or UDP
            ..Default::default()
        };
        assert!(f.matches(&meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, 6, 0)));
        assert!(f.matches(&meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, 17, 0)));
        assert!(!f.matches(&meta(0, 100, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 1, 0))); // ICMP
    }

    #[test]
    fn test_filter_src_ip_cidr() {
        let f = Filter {
            src_ips: vec![IpNet::parse("10.0.0.0/8").unwrap()],
            ..Default::default()
        };
        assert!(f.matches(&meta(0, 60, v4(10, 1, 2, 3), v4(8, 8, 8, 8), 0, 0, 17, 0)));
        assert!(!f.matches(&meta(0, 60, v4(11, 0, 0, 1), v4(8, 8, 8, 8), 0, 0, 17, 0)));
    }

    #[test]
    fn test_filter_dst_ip() {
        let f = Filter {
            dst_ips: vec![IpNet::parse("8.8.8.8").unwrap()],
            ..Default::default()
        };
        assert!(f.matches(&meta(0, 60, v4(1, 2, 3, 4), v4(8, 8, 8, 8), 0, 0, 17, 0)));
        assert!(!f.matches(&meta(0, 60, v4(1, 2, 3, 4), v4(1, 1, 1, 1), 0, 0, 17, 0)));
    }

    #[test]
    fn test_filter_ip_either_endpoint() {
        let f = Filter {
            ips: vec![IpNet::parse("10.0.0.1").unwrap()],
            ..Default::default()
        };
        // Matches if src OR dst is 10.0.0.1
        assert!(f.matches(&meta(0, 60, v4(10, 0, 0, 1), v4(8, 8, 8, 8), 0, 0, 17, 0)));
        assert!(f.matches(&meta(0, 60, v4(8, 8, 8, 8), v4(10, 0, 0, 1), 0, 0, 17, 0)));
        assert!(!f.matches(&meta(0, 60, v4(1, 2, 3, 4), v4(5, 6, 7, 8), 0, 0, 17, 0)));
    }

    #[test]
    fn test_filter_src_ip_multiple_or() {
        let f = Filter {
            src_ips: vec![
                IpNet::parse("10.0.0.1").unwrap(),
                IpNet::parse("192.168.0.0/16").unwrap(),
            ],
            ..Default::default()
        };
        assert!(f.matches(&meta(0, 60, v4(10, 0, 0, 1), v4(8, 8, 8, 8), 0, 0, 6, 0)));
        assert!(f.matches(&meta(0, 60, v4(192, 168, 1, 2), v4(8, 8, 8, 8), 0, 0, 6, 0)));
        assert!(!f.matches(&meta(0, 60, v4(172, 16, 0, 1), v4(8, 8, 8, 8), 0, 0, 6, 0)));
    }

    #[test]
    fn test_filter_dst_port() {
        let f = Filter {
            dst_ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            ..Default::default()
        };
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
        let f = Filter {
            ports: vec![PortRange {
                start: 8000,
                end: 9000,
            }],
            ..Default::default()
        };
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
        let f = Filter {
            dst_ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            ..Default::default()
        };
        // ICMP packet with dst_port=0: port filter is ignored, but protocol
        // filter is not set, so the only active filter is dst_port which
        // doesn't apply to ICMP → packet should pass.
        assert!(f.matches(&meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 1, 0)));
    }

    #[test]
    fn test_filter_flow_id() {
        let key = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1234, 443, 6);
        let id = key.flow_id(false);
        let f = Filter {
            flow_ids: [id].into_iter().collect(),
            ..Default::default()
        };

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
    fn test_filter_flow_id_multiple() {
        let keys: Vec<FlowKey> = (0u8..4)
            .map(|i| {
                FlowKey::new(
                    v4(10, 0, 0, i + 1),
                    v4(10, 0, 0, 100),
                    1000 + i as u16,
                    80,
                    6,
                )
            })
            .collect();
        let ids: Vec<u64> = keys.iter().map(|k| k.flow_id(false)).collect();

        let f = Filter {
            flow_ids: ids[..3].iter().copied().collect(), // allow first three
            ..Default::default()
        };

        for (i, key) in keys.iter().enumerate() {
            let pkt = PacketMeta {
                timestamp_ns: 0,
                captured_len: 60,
                flow_key: Some(key.clone()),
                tcp_flags: 0,
            };
            if i < 3 {
                assert!(f.matches(&pkt), "flow {i} should be allowed");
            } else {
                assert!(!f.matches(&pkt), "flow {i} should be blocked");
            }
        }
    }

    #[test]
    fn test_filter_flow_id_empty_allows_all() {
        // An empty flow_ids set must not filter anything.
        let f = Filter::default();
        assert!(f.flow_ids.is_empty());
        let pkt = meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 80, 6, 0);
        assert!(f.matches(&pkt));
    }

    #[test]
    fn test_filter_flow_id_non_ip_blocked() {
        // A non-IP packet has no flow key; if flow_ids is non-empty it should
        // not match (there is no ID to look up).
        let key = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1234, 443, 6);
        let f = Filter {
            flow_ids: [key.flow_id(false)].into_iter().collect(),
            ..Default::default()
        };

        let no_key = PacketMeta {
            timestamp_ns: 0,
            captured_len: 60,
            flow_key: None,
            tcp_flags: 0,
        };
        assert!(!f.matches(&no_key));
    }

    #[test]
    fn test_filter_tcp_flags() {
        let f = Filter {
            tcp_flags: Some(TcpFlagsFilter::parse("SYN").unwrap()),
            ..Default::default()
        };

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
        let f = Filter {
            protocols: vec![6],
            dst_ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            src_ips: vec![IpNet::parse("10.0.0.0/8").unwrap()],
            ..Default::default()
        };

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
        let f = Filter {
            protocols: vec![6],
            ..Default::default()
        };
        assert!(!f.matches(&no_flow_meta(0, 100)));
    }

    #[test]
    fn test_filter_non_ip_passes_when_only_length_filter() {
        let f = Filter {
            min_len: Some(50),
            ..Default::default()
        };
        assert!(f.matches(&no_flow_meta(0, 60)));
        assert!(!f.matches(&no_flow_meta(0, 40)));
    }

    // ── Filter::validate ─────────────────────────────────────────────────────

    #[test]
    fn test_filter_validate_accepts_default() {
        assert!(Filter::default().validate().is_ok());
    }

    #[test]
    fn test_filter_validate_rejects_inverted_timestamp_window() {
        let f = Filter {
            from_ns: Some(2_000),
            to_ns: Some(1_000),
            ..Default::default()
        };
        assert!(matches!(
            f.validate(),
            Err(FilterError::InvalidRange {
                field: "timestamp",
                lo: 2_000,
                hi: 1_000
            })
        ));
    }

    #[test]
    fn test_filter_validate_rejects_inverted_length_window() {
        let f = Filter {
            min_len: Some(1500),
            max_len: Some(64),
            ..Default::default()
        };
        assert!(matches!(
            f.validate(),
            Err(FilterError::InvalidRange {
                field: "length",
                ..
            })
        ));
    }

    #[test]
    fn test_filter_validate_accepts_equal_bounds() {
        // lo == hi defines a single-point window — that's a legitimate intent,
        // not a misconfiguration, so it must pass.
        let f = Filter {
            from_ns: Some(1_000),
            to_ns: Some(1_000),
            min_len: Some(100),
            max_len: Some(100),
            ..Default::default()
        };
        assert!(f.validate().is_ok());
    }

    #[test]
    fn test_filter_validate_checks_rules_too() {
        // An inverted range inside a chained rule must also be caught.
        let rule = FilterRule {
            op: Op::And,
            from_ns: Some(100),
            to_ns: Some(50),
            ..FilterRule::default()
        };
        let f = Filter {
            rules: vec![rule],
            ..Default::default()
        };
        assert!(matches!(
            f.validate(),
            Err(FilterError::InvalidRange {
                field: "rule timestamp",
                ..
            })
        ));
    }

    // ── Filter::matches with negate and rule chains ──────────────────────────

    #[test]
    fn test_filter_negate_inverts_base_result() {
        // Base body matches TCP. With negate=true, only non-TCP packets pass.
        let f = Filter {
            negate: true,
            protocols: vec![6],
            ..Default::default()
        };
        let tcp_pkt = meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 80, 80, 6, 0);
        let udp_pkt = meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 80, 80, 17, 0);
        assert!(!f.matches(&tcp_pkt));
        assert!(f.matches(&udp_pkt));
    }

    #[test]
    fn test_filter_rule_chain_and_or_not() {
        // Build a filter equivalent to: (proto=tcp) AND (dst_port=443)
        let mut f = Filter {
            protocols: vec![6],
            ..Default::default()
        };
        f.rules.push(FilterRule {
            op: Op::And,
            dst_ports: vec![PortRange::parse("443").unwrap()],
            ..FilterRule::default()
        });
        let tcp_443 = meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 443, 6, 0);
        let tcp_80 = meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 80, 6, 0);
        let udp_443 = meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 443, 17, 0);
        assert!(f.matches(&tcp_443));
        assert!(!f.matches(&tcp_80));
        assert!(!f.matches(&udp_443));

        // OR rule: (proto=tcp) OR (proto=udp)
        let mut f = Filter {
            protocols: vec![6],
            ..Default::default()
        };
        f.rules.push(FilterRule {
            op: Op::Or,
            protocols: vec![17],
            ..FilterRule::default()
        });
        assert!(f.matches(&tcp_443));
        assert!(f.matches(&udp_443));
        let icmp = meta(0, 60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 1, 0);
        assert!(!f.matches(&icmp));

        // NOT rule: (proto=tcp) AND NOT (dst_port=80) — exclude TCP port 80.
        let mut f = Filter {
            protocols: vec![6],
            ..Default::default()
        };
        f.rules.push(FilterRule {
            op: Op::Not,
            dst_ports: vec![PortRange::parse("80").unwrap()],
            ..FilterRule::default()
        });
        assert!(f.matches(&tcp_443));
        assert!(!f.matches(&tcp_80));
    }
}
