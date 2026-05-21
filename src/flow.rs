//! Shared flow key definition and deterministic flow ID computation.
//!
//! [`FlowKey`] is the canonical 5-tuple used throughout the crate.
//! It is placed here (rather than in `stats`) so that `pcap` can depend on it
//! without creating a circular module dependency.

use std::net::IpAddr;

/// Normalise an IP address: IPv4-mapped IPv6 addresses (`::ffff:A.B.C.D`) are
/// converted to their plain IPv4 form so that `10.0.0.1` and `::ffff:10.0.0.1`
/// produce the same [`FlowKey`].
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// A 5-tuple that uniquely identifies a network flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP, 1 = ICMP, …).
    pub protocol: u8,
}

impl FlowKey {
    /// Create a new flow key, normalising IPv4-mapped IPv6 addresses to IPv4.
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip: normalize_ip(src_ip),
            dst_ip: normalize_ip(dst_ip),
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Compute a deterministic 64-bit flow ID using rapidhash.
    ///
    /// **Bidirectional** (default): A→B and B→A produce the same ID by
    /// canonicalising the two endpoints so that `min_ep` always comes first.
    ///
    /// **Unidirectional**: hash the 5-tuple as-is, direction-sensitive.
    ///
    /// IPs are serialised as fixed-width big-endian bytes (4 for IPv4,
    /// 16 for IPv6) prefixed with a family tag to prevent collisions between
    /// address families.
    pub fn flow_id(&self, unidirectional: bool) -> u64 {
        let mut buf = [0u8; 38]; // 1 + 16 + 2 + 1 + 16 + 2 = 38
        let mut pos = 0;

        let (ep_a_ip, ep_a_port, ep_b_ip, ep_b_port) = if unidirectional {
            (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        } else {
            canonicalize(self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        };

        pos += write_ip(&mut buf[pos..], ep_a_ip);
        buf[pos..pos + 2].copy_from_slice(&ep_a_port.to_be_bytes());
        pos += 2;
        pos += write_ip(&mut buf[pos..], ep_b_ip);
        buf[pos..pos + 2].copy_from_slice(&ep_b_port.to_be_bytes());
        pos += 2;
        buf[pos] = self.protocol;
        pos += 1;

        rapidhash::v2::rapidhash_v2_2(&buf[..pos])
    }
}

/// Canonicalise two endpoints so the result is consistent regardless of direction.
fn canonicalize(
    ip_a: IpAddr,
    port_a: u16,
    ip_b: IpAddr,
    port_b: u16,
) -> (IpAddr, u16, IpAddr, u16) {
    let bytes_a = ip_to_bytes(ip_a);
    let bytes_b = ip_to_bytes(ip_b);

    if (bytes_a.as_slice(), port_a) <= (bytes_b.as_slice(), port_b) {
        (ip_a, port_a, ip_b, port_b)
    } else {
        (ip_b, port_b, ip_a, port_a)
    }
}

fn ip_to_bytes(ip: IpAddr) -> [u8; 17] {
    let mut buf = [0u8; 17];
    match ip {
        IpAddr::V4(v4) => {
            buf[0] = 4;
            buf[1..5].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf[0] = 6;
            buf[1..17].copy_from_slice(&v6.octets());
        }
    }
    buf
}

/// Write an IP address into `out`, returning the number of bytes written.
fn write_ip(out: &mut [u8], ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            out[0] = 4;
            out[1..5].copy_from_slice(&v4.octets());
            5
        }
        IpAddr::V6(v6) => {
            out[0] = 6;
            out[1..17].copy_from_slice(&v6.octets());
            17
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v4mapped(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        // ::ffff:a.b.c.d
        IpAddr::V6(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())
    }

    #[test]
    fn test_normalize_ip_plain_v4_unchanged() {
        let ip = v4(10, 0, 0, 1);
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn test_normalize_ip_plain_v6_unchanged() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn test_normalize_ip_v4mapped_converts_to_v4() {
        let mapped = v4mapped(10, 0, 0, 1);
        let expected = v4(10, 0, 0, 1);
        assert_eq!(normalize_ip(mapped), expected);
    }

    #[test]
    fn test_flow_key_new_normalizes_v4mapped() {
        // ::ffff:10.0.0.1 and 10.0.0.1 must produce identical FlowKeys.
        let key_plain = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1000, 443, 6);
        let key_mapped = FlowKey::new(v4mapped(10, 0, 0, 1), v4mapped(10, 0, 0, 2), 1000, 443, 6);
        assert_eq!(key_plain, key_mapped);
        assert_eq!(key_plain.flow_id(false), key_mapped.flow_id(false));
    }

    #[test]
    fn test_flow_id_bidirectional_is_symmetric() {
        let fwd = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 12345, 443, 6);
        let rev = FlowKey::new(v4(10, 0, 0, 2), v4(10, 0, 0, 1), 443, 12345, 6);
        assert_eq!(fwd.flow_id(false), rev.flow_id(false));
    }

    #[test]
    fn test_flow_id_unidirectional_differs_by_direction() {
        let fwd = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 12345, 443, 6);
        let rev = FlowKey::new(v4(10, 0, 0, 2), v4(10, 0, 0, 1), 443, 12345, 6);
        assert_ne!(fwd.flow_id(true), rev.flow_id(true));
    }

    #[test]
    fn test_flow_id_different_protocols_differ() {
        let tcp = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 12345, 443, 6);
        let udp = FlowKey::new(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 12345, 443, 17);
        assert_ne!(tcp.flow_id(false), udp.flow_id(false));
    }

    #[test]
    fn test_flow_id_deterministic() {
        let key = FlowKey::new(v4(192, 168, 1, 1), v4(8, 8, 8, 8), 54321, 53, 17);
        assert_eq!(key.flow_id(false), key.flow_id(false));
    }

    #[test]
    fn test_flow_id_v4mapped_same_as_v4() {
        // Bidirectional flow IDs must match regardless of whether the IP was
        // presented as plain IPv4 or IPv4-mapped IPv6.
        let plain = FlowKey::new(v4(192, 168, 1, 1), v4(8, 8, 8, 8), 54321, 53, 17);
        let mapped = FlowKey::new(
            v4mapped(192, 168, 1, 1),
            v4mapped(8, 8, 8, 8),
            54321,
            53,
            17,
        );
        assert_eq!(plain.flow_id(false), mapped.flow_id(false));
        assert_eq!(plain.flow_id(true), mapped.flow_id(true));
    }
}
