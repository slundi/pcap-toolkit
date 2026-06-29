//! Pure-Rust tcpdump/libpcap-style BPF expression filter.
//!
//! # Grammar (supported subset)
//!
//! Reference: <https://biot.com/capstats/bpf.html>
//!
//! ```text
//! expr      = or_expr
//! or_expr   = and_expr  ('or'  and_expr)*
//! and_expr  = not_expr  ('and' not_expr)*
//! not_expr  = 'not' not_expr | '(' expr ')' | primitive
//! primitive = proto_kw ['host'|'net'|'port'|'portrange' …]
//!           | dir ('host'|'net'|'port'|'portrange') …
//!           | ('host'|'net'|'port'|'portrange') …
//!           | 'proto' number
//!           | 'len' cmp_op number
//! proto_kw  = 'tcp'|'udp'|'icmp'|'icmp6'|'ip'|'ip6'|'arp'
//! dir       = 'src' | 'dst' | 'src or dst' | 'src and dst'
//! cmp_op    = '>' | '<' | '>=' | '<=' | '==' | '!='
//! ```
//!
//! Sugar: `tcp port 443` expands to `tcp and port 443`.
//! `arp` matches non-IP frames (best-effort: any packet with no parsed flow key).

use thiserror::Error;

use crate::filter::{IpNet, PacketMeta, PortRange};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error returned when a BPF expression cannot be parsed.
#[derive(Debug, Error)]
#[error("BPF parse error at column {col}: {message}")]
pub struct BpfError {
    pub message: String,
    pub col: usize,
}

// ── Tokeniser ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    LParen,
    RParen,
    Gt,
    Lt,
    Ge,
    Le,
    EqEq,
    Ne,
}

/// Scan `input` into a flat token list annotated with byte offsets.
fn tokenize(input: &str) -> Result<Vec<(Tok, usize)>, BpfError> {
    let mut out = Vec::new();
    let b = input.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let col = i;
        match b[i] {
            b'(' => {
                out.push((Tok::LParen, col));
                i += 1;
            }
            b')' => {
                out.push((Tok::RParen, col));
                i += 1;
            }
            b'>' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push((Tok::Ge, col));
                    i += 2;
                } else {
                    out.push((Tok::Gt, col));
                    i += 1;
                }
            }
            b'<' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push((Tok::Le, col));
                    i += 2;
                } else {
                    out.push((Tok::Lt, col));
                    i += 1;
                }
            }
            b'=' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push((Tok::EqEq, col));
                    i += 2;
                } else {
                    return Err(BpfError {
                        message: "bare '=' — did you mean '=='?".into(),
                        col,
                    });
                }
            }
            b'!' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push((Tok::Ne, col));
                    i += 2;
                } else {
                    return Err(BpfError {
                        message: "bare '!' — did you mean '!='?".into(),
                        col,
                    });
                }
            }
            _ => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric()
                        || matches!(b[i], b'.' | b':' | b'/' | b'-' | b'_'))
                {
                    i += 1;
                }
                if i == start {
                    return Err(BpfError {
                        message: format!("unexpected character '{}'", b[col] as char),
                        col,
                    });
                }
                out.push((Tok::Word(input[start..i].to_owned()), start));
            }
        }
    }
    Ok(out)
}

// ── AST ───────────────────────────────────────────────────────────────────────

/// Direction qualifier for host / net / port primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Source endpoint only.
    Src,
    /// Destination endpoint only.
    Dst,
    /// Either endpoint (default when no direction qualifier is given, and for
    /// both `src or dst` and `src and dst`).
    Either,
}

/// Comparison operator used in `len` expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Gt,
    Lt,
    Ge,
    Le,
    Eq,
    Ne,
}

/// A compiled BPF expression tree.
///
/// Construct with [`parse`] and evaluate per-packet with [`BpfExpr::eval`].
#[derive(Debug, Clone)]
pub enum BpfExpr {
    /// Both sub-expressions must match.
    And(Box<Self>, Box<Self>),
    /// Either sub-expression must match.
    Or(Box<Self>, Box<Self>),
    /// Sub-expression must *not* match.
    Not(Box<Self>),
    /// IP protocol number (`tcp`=6, `udp`=17, `icmp`=1, `icmp6`=58, `proto N`).
    IpProto(u8),
    /// IPv4 packet (`ip` keyword).
    Ip,
    /// IPv6 packet (`ip6` keyword).
    Ip6,
    /// ARP frame (`arp` keyword). Best-effort: matches any non-IP packet
    /// (i.e. packets for which etherparse produces no flow key).
    Arp,
    /// Exact host or prefix match on one or both endpoints.
    Host { dir: Dir, net: IpNet },
    /// Network prefix (CIDR) match on one or both endpoints.
    Net { dir: Dir, net: IpNet },
    /// Port or port-range match (TCP/UDP only; silently passes other protocols).
    Port { dir: Dir, range: PortRange },
    /// Captured-length comparison (`len > N`, `len <= N`, …).
    Len { op: CmpOp, val: u32 },
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Maximum grammar nesting depth accepted by the parser.
///
/// Bounds both parse-time stack growth and the depth of the produced
/// `BpfExpr` tree (and therefore the depth of `eval` recursion per packet).
/// Real-world tcpdump filters rarely exceed depth 10; 128 leaves ample
/// headroom while keeping adversarial input from blowing the stack.
pub const MAX_PARSE_DEPTH: usize = 128;

struct Parser {
    toks: Vec<(Tok, usize)>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|(t, _)| t)
    }

    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Word(w)) => Some(w.as_str()),
            _ => None,
        }
    }

    fn word_at(&self, offset: usize) -> Option<&str> {
        match self.toks.get(self.pos + offset) {
            Some((Tok::Word(w), _)) => Some(w.as_str()),
            _ => None,
        }
    }

    fn col(&self) -> usize {
        self.toks.get(self.pos).map(|(_, c)| *c).unwrap_or(0)
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn err(&self, msg: impl Into<String>) -> BpfError {
        BpfError {
            message: msg.into(),
            col: self.col(),
        }
    }

    fn expect_word(&mut self) -> Result<String, BpfError> {
        match self.toks.get(self.pos) {
            Some((Tok::Word(w), _)) => {
                let w = w.clone();
                self.pos += 1;
                Ok(w)
            }
            _ => Err(self.err("expected identifier or value")),
        }
    }

    // ── Grammar rules ──────────────────────────────────────────────────────

    fn parse_expr(&mut self) -> Result<BpfExpr, BpfError> {
        let expr = self.parse_or()?;
        if self.pos < self.toks.len() {
            return Err(self.err(format!(
                "unexpected token after expression: {:?}",
                self.peek_word().unwrap_or("?")
            )));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<BpfExpr, BpfError> {
        self.enter_depth()?;
        let mut left = self.parse_and()?;
        while self.peek_word() == Some("or") {
            self.advance();
            let right = self.parse_and()?;
            left = BpfExpr::Or(Box::new(left), Box::new(right));
        }
        self.depth -= 1;
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<BpfExpr, BpfError> {
        let mut left = self.parse_not()?;
        while self.peek_word() == Some("and") {
            self.advance();
            let right = self.parse_not()?;
            left = BpfExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<BpfExpr, BpfError> {
        if self.peek_word() == Some("not") {
            self.advance();
            self.enter_depth()?;
            let inner = self.parse_not()?; // right-associative
            self.depth -= 1;
            return Ok(BpfExpr::Not(Box::new(inner)));
        }
        if self.peek() == Some(&Tok::LParen) {
            self.advance();
            let inner = self.parse_or()?;
            if self.peek() != Some(&Tok::RParen) {
                return Err(self.err("expected ')'"));
            }
            self.advance();
            return Ok(inner);
        }
        self.parse_primitive()
    }

    fn enter_depth(&mut self) -> Result<(), BpfError> {
        if self.depth >= MAX_PARSE_DEPTH {
            return Err(self.err(format!(
                "expression nests more than {MAX_PARSE_DEPTH} levels deep"
            )));
        }
        self.depth += 1;
        Ok(())
    }

    fn parse_primitive(&mut self) -> Result<BpfExpr, BpfError> {
        // Try to consume a direction prefix (src / dst), but only when it is
        // immediately followed by a type keyword.
        let dir = self.parse_dir();

        let col = self.col();
        let word = match self.peek_word() {
            Some(w) => w.to_owned(),
            None => {
                if dir != Dir::Either {
                    return Err(
                        self.err("expected 'host', 'net', 'port', or 'portrange' after direction")
                    );
                }
                return Err(self.err("expected primitive"));
            }
        };

        // If a direction was consumed, the next token must be a type keyword.
        if dir != Dir::Either {
            return self.parse_type_prim(dir);
        }

        match word.as_str() {
            "tcp" => {
                self.advance();
                self.maybe_compound(BpfExpr::IpProto(6))
            }
            "udp" => {
                self.advance();
                self.maybe_compound(BpfExpr::IpProto(17))
            }
            "icmp" => {
                self.advance();
                self.maybe_compound(BpfExpr::IpProto(1))
            }
            "icmp6" | "icmpv6" => {
                self.advance();
                self.maybe_compound(BpfExpr::IpProto(58))
            }
            "ip" => {
                self.advance();
                self.maybe_compound(BpfExpr::Ip)
            }
            "ip6" => {
                self.advance();
                self.maybe_compound(BpfExpr::Ip6)
            }
            "arp" => {
                self.advance();
                Ok(BpfExpr::Arp)
            }
            "proto" => {
                self.advance();
                let s = self.expect_word()?;
                let n: u8 = s.parse().map_err(|_| BpfError {
                    message: format!("expected protocol number 0-255, got '{s}'"),
                    col,
                })?;
                Ok(BpfExpr::IpProto(n))
            }
            "len" => {
                self.advance();
                let op = self.parse_cmp_op()?;
                let s = self.expect_word()?;
                let n: u32 = s
                    .parse()
                    .map_err(|_| self.err(format!("expected number after 'len', got '{s}'")))?;
                Ok(BpfExpr::Len { op, val: n })
            }
            "host" | "net" | "port" | "portrange" => self.parse_type_prim(Dir::Either),
            _ => Err(BpfError {
                message: format!("unknown primitive '{word}'"),
                col,
            }),
        }
    }

    /// After a protocol keyword, check whether a type keyword follows.
    ///
    /// `tcp port 443` → `And(IpProto(6), Port(Either, 443-443))`.
    fn maybe_compound(&mut self, proto_expr: BpfExpr) -> Result<BpfExpr, BpfError> {
        if self.is_type_keyword() {
            let type_expr = self.parse_type_prim(Dir::Either)?;
            Ok(BpfExpr::And(Box::new(proto_expr), Box::new(type_expr)))
        } else {
            Ok(proto_expr)
        }
    }

    fn is_type_keyword(&self) -> bool {
        matches!(
            self.peek_word(),
            Some("host" | "net" | "port" | "portrange")
        )
    }

    /// Try to consume a direction qualifier (`src` / `dst`).
    ///
    /// Only advances `pos` when a type keyword follows, so a bare `src` that
    /// is not a direction qualifier is left untouched (which results in a parse
    /// error in `parse_primitive`).
    ///
    /// Handles `src or dst` and `src and dst` — both map to [`Dir::Either`].
    fn parse_dir(&mut self) -> Dir {
        let word = match self.peek_word() {
            Some(w @ ("src" | "dst")) => w.to_owned(),
            _ => return Dir::Either,
        };

        // Check for "src or dst <type>" or "src and dst <type>".
        if matches!(self.word_at(1), Some("or" | "and"))
            && matches!(self.word_at(2), Some("src" | "dst"))
            && matches!(self.word_at(3), Some("host" | "net" | "port" | "portrange"))
        {
            self.pos += 3; // consume: first-dir, or/and, second-dir
            return Dir::Either;
        }

        // Simple "src <type>" or "dst <type>".
        if matches!(self.word_at(1), Some("host" | "net" | "port" | "portrange")) {
            self.advance();
            return if word == "src" { Dir::Src } else { Dir::Dst };
        }

        Dir::Either // not a direction context — do not consume
    }

    fn parse_type_prim(&mut self, dir: Dir) -> Result<BpfExpr, BpfError> {
        let kw = self.expect_word()?;
        match kw.as_str() {
            "host" => {
                let s = self.expect_word()?;
                let net = IpNet::parse(&s)
                    .map_err(|_| self.err(format!("invalid host address '{s}'")))?;
                Ok(BpfExpr::Host { dir, net })
            }
            "net" => {
                let s = self.expect_word()?;
                let net = IpNet::parse(&s)
                    .map_err(|_| self.err(format!("invalid network/CIDR '{s}'")))?;
                Ok(BpfExpr::Net { dir, net })
            }
            "port" | "portrange" => {
                let s = self.expect_word()?;
                let range = PortRange::parse(&s)
                    .map_err(|_| self.err(format!("invalid port or range '{s}'")))?;
                Ok(BpfExpr::Port { dir, range })
            }
            other => Err(self.err(format!("expected host/net/port/portrange, got '{other}'"))),
        }
    }

    fn parse_cmp_op(&mut self) -> Result<CmpOp, BpfError> {
        let col = self.col();
        let op = match self.peek() {
            Some(Tok::Gt) => CmpOp::Gt,
            Some(Tok::Lt) => CmpOp::Lt,
            Some(Tok::Ge) => CmpOp::Ge,
            Some(Tok::Le) => CmpOp::Le,
            Some(Tok::EqEq) => CmpOp::Eq,
            Some(Tok::Ne) => CmpOp::Ne,
            _ => {
                return Err(BpfError {
                    message: "expected comparison operator (>, <, >=, <=, ==, !=)".into(),
                    col,
                });
            }
        };
        self.advance();
        Ok(op)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a tcpdump/libpcap-style BPF filter expression into a compiled tree.
///
/// # Errors
/// Returns [`BpfError`] with the column offset of the first invalid token.
///
/// # Examples
/// ```
/// use pcap_toolkit::bpf::parse;
/// let expr = parse("tcp and dst port 443").unwrap();
/// ```
pub fn parse(input: &str) -> Result<BpfExpr, BpfError> {
    let toks = tokenize(input)?;
    if toks.is_empty() {
        return Err(BpfError {
            message: "empty filter expression".into(),
            col: 0,
        });
    }
    let mut parser = Parser {
        toks,
        pos: 0,
        depth: 0,
    };
    parser.parse_expr()
}

// ── Evaluation ────────────────────────────────────────────────────────────────

impl BpfExpr {
    /// Evaluate this expression against packet metadata.
    ///
    /// Returns `true` if the packet passes the filter.
    pub fn eval(&self, meta: &PacketMeta) -> bool {
        match self {
            Self::And(a, b) => a.eval(meta) && b.eval(meta),
            Self::Or(a, b) => a.eval(meta) || b.eval(meta),
            Self::Not(inner) => !inner.eval(meta),

            Self::IpProto(proto) => meta
                .flow_key
                .as_ref()
                .map(|k| k.protocol == *proto)
                .unwrap_or(false),

            Self::Ip => meta
                .flow_key
                .as_ref()
                .map(|k| k.src_ip.is_ipv4())
                .unwrap_or(false),

            Self::Ip6 => meta
                .flow_key
                .as_ref()
                .map(|k| k.src_ip.is_ipv6())
                .unwrap_or(false),

            // ARP and other non-IP frames produce no flow key in our pipeline.
            Self::Arp => meta.flow_key.is_none(),

            Self::Host { dir, net } | Self::Net { dir, net } => {
                let Some(k) = &meta.flow_key else {
                    return false;
                };
                match dir {
                    Dir::Src => net.contains(k.src_ip),
                    Dir::Dst => net.contains(k.dst_ip),
                    Dir::Either => net.contains(k.src_ip) || net.contains(k.dst_ip),
                }
            }

            Self::Port { dir, range } => {
                let Some(k) = &meta.flow_key else {
                    return false;
                };
                // Port filters are silently ignored for non-TCP/UDP protocols.
                if !matches!(k.protocol, 6 | 17) {
                    return true;
                }
                match dir {
                    Dir::Src => range.contains(k.src_port),
                    Dir::Dst => range.contains(k.dst_port),
                    Dir::Either => range.contains(k.src_port) || range.contains(k.dst_port),
                }
            }

            Self::Len { op, val } => {
                let l = meta.captured_len;
                match op {
                    CmpOp::Gt => l > *val,
                    CmpOp::Lt => l < *val,
                    CmpOp::Ge => l >= *val,
                    CmpOp::Le => l <= *val,
                    CmpOp::Eq => l == *val,
                    CmpOp::Ne => l != *val,
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn make_meta(
        caplen: u32,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        proto: u8,
    ) -> PacketMeta {
        use crate::flow::FlowKey;
        PacketMeta {
            timestamp_ns: 0,
            captured_len: caplen,
            flow_key: Some(FlowKey::new(src, dst, sport, dport, proto)),
            tcp_flags: 0,
        }
    }

    fn no_ip(caplen: u32) -> PacketMeta {
        PacketMeta {
            timestamp_ns: 0,
            captured_len: caplen,
            flow_key: None,
            tcp_flags: 0,
        }
    }

    // ── Parse ──────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_proto_keywords() {
        assert!(matches!(parse("tcp").unwrap(), BpfExpr::IpProto(6)));
        assert!(matches!(parse("udp").unwrap(), BpfExpr::IpProto(17)));
        assert!(matches!(parse("icmp").unwrap(), BpfExpr::IpProto(1)));
        assert!(matches!(parse("icmp6").unwrap(), BpfExpr::IpProto(58)));
        assert!(matches!(parse("icmpv6").unwrap(), BpfExpr::IpProto(58)));
        assert!(matches!(parse("ip").unwrap(), BpfExpr::Ip));
        assert!(matches!(parse("ip6").unwrap(), BpfExpr::Ip6));
        assert!(matches!(parse("arp").unwrap(), BpfExpr::Arp));
    }

    #[test]
    fn test_parse_proto_number() {
        assert!(matches!(parse("proto 17").unwrap(), BpfExpr::IpProto(17)));
        assert!(matches!(parse("proto 50").unwrap(), BpfExpr::IpProto(50)));
    }

    #[test]
    fn test_parse_host_either() {
        assert!(matches!(
            parse("host 10.0.0.1").unwrap(),
            BpfExpr::Host {
                dir: Dir::Either,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_src_dst_host() {
        assert!(matches!(
            parse("src host 10.0.0.1").unwrap(),
            BpfExpr::Host { dir: Dir::Src, .. }
        ));
        assert!(matches!(
            parse("dst host 10.0.0.1").unwrap(),
            BpfExpr::Host { dir: Dir::Dst, .. }
        ));
    }

    #[test]
    fn test_parse_net_cidr() {
        assert!(matches!(
            parse("src net 10.0.0.0/8").unwrap(),
            BpfExpr::Net { dir: Dir::Src, .. }
        ));
    }

    #[test]
    fn test_parse_port_and_portrange() {
        assert!(matches!(
            parse("dst port 443").unwrap(),
            BpfExpr::Port { dir: Dir::Dst, .. }
        ));
        assert!(matches!(
            parse("portrange 1024-65535").unwrap(),
            BpfExpr::Port {
                dir: Dir::Either,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_src_or_dst_direction() {
        let e = parse("src or dst port 80").unwrap();
        assert!(matches!(
            e,
            BpfExpr::Port {
                dir: Dir::Either,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_src_and_dst_direction() {
        let e = parse("src and dst port 80").unwrap();
        assert!(matches!(
            e,
            BpfExpr::Port {
                dir: Dir::Either,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_len_all_ops() {
        assert!(matches!(
            parse("len > 100").unwrap(),
            BpfExpr::Len {
                op: CmpOp::Gt,
                val: 100
            }
        ));
        assert!(matches!(
            parse("len < 100").unwrap(),
            BpfExpr::Len {
                op: CmpOp::Lt,
                val: 100
            }
        ));
        assert!(matches!(
            parse("len >= 64").unwrap(),
            BpfExpr::Len {
                op: CmpOp::Ge,
                val: 64
            }
        ));
        assert!(matches!(
            parse("len <= 1500").unwrap(),
            BpfExpr::Len {
                op: CmpOp::Le,
                val: 1500
            }
        ));
        assert!(matches!(
            parse("len == 60").unwrap(),
            BpfExpr::Len {
                op: CmpOp::Eq,
                val: 60
            }
        ));
        assert!(matches!(
            parse("len != 0").unwrap(),
            BpfExpr::Len {
                op: CmpOp::Ne,
                val: 0
            }
        ));
    }

    #[test]
    fn test_parse_not() {
        assert!(matches!(parse("not tcp").unwrap(), BpfExpr::Not(_)));
    }

    #[test]
    fn test_parse_and_or_precedence() {
        // "tcp or udp and dst port 443" → tcp OR (udp AND dst port 443)
        let e = parse("tcp or udp and dst port 443").unwrap();
        let BpfExpr::Or(left, right) = e else {
            panic!("expected Or")
        };
        assert!(matches!(*left, BpfExpr::IpProto(6)));
        assert!(matches!(*right, BpfExpr::And(_, _)));
    }

    #[test]
    fn test_parse_tcp_port_sugar() {
        // "tcp port 443" → And(IpProto(6), Port(Either, 443))
        let BpfExpr::And(l, r) = parse("tcp port 443").unwrap() else {
            panic!()
        };
        assert!(matches!(*l, BpfExpr::IpProto(6)));
        assert!(matches!(
            *r,
            BpfExpr::Port {
                dir: Dir::Either,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_parens() {
        let BpfExpr::Not(inner) = parse("not (tcp or udp)").unwrap() else {
            panic!()
        };
        assert!(matches!(*inner, BpfExpr::Or(_, _)));
    }

    #[test]
    fn test_parse_ipv6_host() {
        assert!(parse("host 2001:db8::1").is_ok());
        assert!(parse("dst host ::1").is_ok());
    }

    #[test]
    fn test_parse_empty_error() {
        assert!(parse("").is_err());
    }

    #[test]
    fn test_parse_unknown_primitive_error() {
        assert!(parse("foobar").is_err());
    }

    #[test]
    fn test_parse_unclosed_paren_error() {
        assert!(parse("(tcp and udp").is_err());
    }

    #[test]
    fn test_parse_bare_equals_error() {
        assert!(parse("len = 100").is_err());
    }

    // ── Eval ───────────────────────────────────────────────────────────────

    #[test]
    fn test_eval_proto_match() {
        let tcp = make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 80, 6);
        let udp = make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 53, 17);
        let expr = parse("tcp").unwrap();
        assert!(expr.eval(&tcp));
        assert!(!expr.eval(&udp));
    }

    #[test]
    fn test_eval_ip_version() {
        let v4pkt = make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1, 2, 6);
        let v6src: IpAddr = "2001:db8::1".parse().unwrap();
        let v6dst: IpAddr = "2001:db8::2".parse().unwrap();
        let v6pkt = make_meta(60, v6src, v6dst, 1, 2, 6);
        assert!(parse("ip").unwrap().eval(&v4pkt));
        assert!(!parse("ip").unwrap().eval(&v6pkt));
        assert!(parse("ip6").unwrap().eval(&v6pkt));
        assert!(!parse("ip6").unwrap().eval(&v4pkt));
    }

    #[test]
    fn test_eval_arp_matches_non_ip() {
        let expr = parse("arp").unwrap();
        assert!(expr.eval(&no_ip(60)));
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 17)));
    }

    #[test]
    fn test_eval_host_either() {
        let expr = parse("host 8.8.8.8").unwrap();
        assert!(expr.eval(&make_meta(60, v4(8, 8, 8, 8), v4(1, 2, 3, 4), 0, 0, 17)));
        assert!(expr.eval(&make_meta(60, v4(1, 2, 3, 4), v4(8, 8, 8, 8), 0, 0, 17)));
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 17)));
    }

    #[test]
    fn test_eval_src_net() {
        let expr = parse("src net 10.0.0.0/8").unwrap();
        assert!(expr.eval(&make_meta(60, v4(10, 1, 2, 3), v4(8, 8, 8, 8), 0, 0, 17)));
        assert!(!expr.eval(&make_meta(60, v4(192, 168, 1, 1), v4(8, 8, 8, 8), 0, 0, 17)));
    }

    #[test]
    fn test_eval_dst_port() {
        let expr = parse("dst port 443").unwrap();
        assert!(expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 443, 6)));
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5001, 80, 6)));
    }

    #[test]
    fn test_eval_portrange() {
        let expr = parse("portrange 1024-65535").unwrap();
        // high-numbered src port matches
        assert!(expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 8080, 80, 6)));
        // both low — no match
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 80, 80, 6)));
    }

    #[test]
    fn test_eval_len() {
        assert!(parse("len > 100").unwrap().eval(&no_ip(200)));
        assert!(!parse("len > 100").unwrap().eval(&no_ip(50)));
        assert!(parse("len <= 40").unwrap().eval(&no_ip(40)));
        assert!(!parse("len <= 40").unwrap().eval(&no_ip(41)));
    }

    #[test]
    fn test_eval_tcp_port_sugar() {
        let expr = parse("tcp port 80").unwrap();
        assert!(expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 80, 6)));
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 80, 17))); // UDP
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 443, 6))); // wrong port
    }

    #[test]
    fn test_eval_not() {
        let expr = parse("not tcp").unwrap();
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 6)));
        assert!(expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, 17)));
    }

    #[test]
    fn test_eval_and_or() {
        let expr = parse("tcp and dst port 443").unwrap();
        assert!(expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 443, 6)));
        assert!(!expr.eval(&make_meta(60, v4(1, 1, 1, 1), v4(2, 2, 2, 2), 5000, 80, 6)));
        assert!(!expr.eval(&make_meta(
            60,
            v4(1, 1, 1, 1),
            v4(2, 2, 2, 2),
            5000,
            443,
            17
        )));
    }

    #[test]
    fn test_eval_complex() {
        // "(tcp or udp) and src net 10.0.0.0/8 and not dst port 80"
        let expr = parse("(tcp or udp) and src net 10.0.0.0/8 and not dst port 80").unwrap();
        // passes: TCP from 10.x, dst 443
        assert!(expr.eval(&make_meta(
            100,
            v4(10, 0, 0, 1),
            v4(8, 8, 8, 8),
            5000,
            443,
            6
        )));
        // fails: TCP from 10.x but dst 80
        assert!(!expr.eval(&make_meta(
            100,
            v4(10, 0, 0, 1),
            v4(8, 8, 8, 8),
            5000,
            80,
            6
        )));
        // fails: correct ports/proto but wrong src net
        assert!(!expr.eval(&make_meta(
            100,
            v4(192, 168, 1, 1),
            v4(8, 8, 8, 8),
            5000,
            443,
            6
        )));
        // fails: ICMP from 10.x
        assert!(!expr.eval(&make_meta(100, v4(10, 0, 0, 1), v4(8, 8, 8, 8), 0, 0, 1)));
    }

    // ── Recursion-depth guard ─────────────────────────────────────────────────

    #[test]
    fn test_parse_rejects_excessive_nesting() {
        // Pathological input: thousands of nested parens. Without a depth
        // guard the recursive-descent parser would blow the stack.
        let n = MAX_PARSE_DEPTH + 50;
        let mut src = String::with_capacity(2 * n + 4);
        for _ in 0..n {
            src.push('(');
        }
        src.push_str("tcp");
        for _ in 0..n {
            src.push(')');
        }
        let err = parse(&src).expect_err("deeply nested input must error");
        assert!(
            err.message.contains("nests more than"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_parse_rejects_excessive_not_chain() {
        // `not not not ...` recurses through parse_not itself.
        let n = MAX_PARSE_DEPTH + 50;
        let mut src = String::with_capacity(4 * n + 4);
        for _ in 0..n {
            src.push_str("not ");
        }
        src.push_str("tcp");
        let err = parse(&src).expect_err("deeply chained not must error");
        assert!(
            err.message.contains("nests more than"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_parse_accepts_moderate_nesting() {
        // Within the limit, parens nest fine.
        let n = 20;
        let mut src = String::with_capacity(2 * n + 4);
        for _ in 0..n {
            src.push('(');
        }
        src.push_str("tcp");
        for _ in 0..n {
            src.push(')');
        }
        assert!(parse(&src).is_ok());
    }
}
