//! Live packet replay onto a real network interface.
//!
//! Reads packets from a PCAP file and injects them via a raw `AF_PACKET`
//! socket (Linux only) using the original or a scaled inter-packet timing.
//!
//! ## Timing modes
//!
//! | CLI flag               | Behaviour                                        |
//! |------------------------|--------------------------------------------------|
//! | *(none)*               | Real-time: honour original inter-packet gaps     |
//! | `--speed 2.0`          | Multiplier: replay 2× faster than original       |
//! | `--speed max`          | No delay — transmit as fast as the NIC allows    |
//! | `--pps 4096`           | Fixed rate: 4 096 packets/second, ignores gaps   |
//!
//! ## Permissions
//!
//! Raw sockets require `CAP_NET_RAW`. If the capability is absent the function
//! returns [`ReplayError::PermissionDenied`] with a remediation hint.

use std::time::{Duration, Instant};

use crate::bpf::BpfExpr;
use crate::error::ReplayError;
use crate::filter::{Filter, PacketMeta};
use crate::pcap::{self, PacketSource};

// ── Public types ─────────────────────────────────────────────────────────────

/// How to pace packet transmission during replay.
///
/// # Sorted input expected
///
/// [`RealTime`](Self::RealTime) and [`Multiplier`](Self::Multiplier) anchor
/// their wall-clock schedule on the first packet's timestamp. Packets whose
/// timestamp is *earlier* than the first packet's are sent immediately (the
/// computed delay saturates to zero). For deterministic timing, the input
/// PCAP should be sorted ascending by capture timestamp — run [`sort_file`]
/// first if you don't trust the source. [`Max`](Self::Max) and
/// [`Pps`](Self::Pps) ignore packet timestamps entirely and are unaffected.
///
/// [`sort_file`]: crate::sort::sort_file
#[derive(Debug, Clone)]
pub enum ReplaySpeed {
    /// Honour original inter-packet timing (the default).
    ///
    /// Requires a sorted PCAP for deterministic pacing; see the enum-level
    /// docs above.
    RealTime,
    /// Scale timing by a multiplier: `>1.0` = faster, `<1.0` = slower.
    ///
    /// Requires a sorted PCAP for deterministic pacing; see the enum-level
    /// docs above.
    Multiplier(f64),
    /// Send as fast as possible with no delay between packets.
    Max,
    /// Fixed transmission rate in packets per second (ignores original timing).
    Pps(u64),
}

impl ReplaySpeed {
    /// Parse a speed string.
    ///
    /// | Input  | Result                    |
    /// |--------|---------------------------|
    /// | `"max"` | [`ReplaySpeed::Max`]     |
    /// | `"1.0"` | [`ReplaySpeed::RealTime`] |
    /// | `"2.5"` | [`ReplaySpeed::Multiplier(2.5)`] |
    ///
    /// Returns `None` for non-positive numbers or unrecognised strings.
    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("max") {
            return Some(ReplaySpeed::Max);
        }
        s.parse::<f64>().ok().filter(|&f| f > 0.0).map(|f| {
            if (f - 1.0).abs() < f64::EPSILON {
                ReplaySpeed::RealTime
            } else {
                ReplaySpeed::Multiplier(f)
            }
        })
    }
}

/// Options for [`replay_file`].
pub struct ReplayOptions {
    /// Network interface names to transmit on (e.g. `["eth0", "eth1"]`).
    /// Each packet is sent to all interfaces (fan-out).
    pub interfaces: Vec<String>,
    /// Packet pacing mode.
    pub speed: ReplaySpeed,
    /// Structured filter applied before sending each packet.
    pub filter: Filter,
    /// BPF expression filter AND-ed with `filter`. `None` = no BPF filter.
    pub bpf_filter: Option<BpfExpr>,
}

/// Summary returned by [`replay_file`] on success.
#[derive(Debug)]
pub struct ReplayReport {
    /// Total packets transmitted.
    pub packets_sent: u64,
    /// Total bytes transmitted (sum of captured lengths).
    pub bytes_sent: u64,
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Replay all packets from `input` onto the network interface in `opts`.
///
/// Packets are read in file order (sort first with `sort_file` if needed).
/// Filters are applied before each packet is sent.
///
/// # Errors
/// Returns [`ReplayError`] on I/O failure, missing `CAP_NET_RAW`,
/// unknown interface name, or if the platform is not Linux.
pub fn replay_file(
    input: impl Into<PacketSource>,
    opts: &ReplayOptions,
) -> Result<ReplayReport, ReplayError> {
    platform::replay_impl(&input.into(), opts)
}

// ── Timing helper (platform-independent) ─────────────────────────────────────

/// Compute how long to wait before sending the next packet.
///
/// - `speed`        — pacing mode
/// - `pkt_ts_ns`    — original capture timestamp of this packet (nanoseconds)
/// - `first_ts_ns`  — mutable slot that stores the first packet's timestamp
/// - `sent_count`   — number of packets already sent (used for PPS mode)
/// - `start_time`   — wall-clock instant when the first packet was sent
pub(crate) fn compute_delay(
    speed: &ReplaySpeed,
    pkt_ts_ns: u64,
    first_ts_ns: &mut Option<u64>,
    sent_count: u64,
    start_time: &Instant,
) -> Duration {
    match speed {
        ReplaySpeed::Max => Duration::ZERO,

        ReplaySpeed::Pps(pps) => {
            if *pps == 0 {
                return Duration::ZERO;
            }
            // Packet N should go out at N * (1_000_000_000 / pps) ns after start.
            // Use u128 to avoid overflow: sent_count * 1e9 wraps u64 after ~18.4 B
            // packets (~5 h at 1 Mpps). The result fits in u64 for any realistic run.
            let target_ns = (sent_count as u128 * 1_000_000_000 / *pps as u128) as u64;
            let elapsed_ns = start_time.elapsed().as_nanos() as u64;
            if target_ns > elapsed_ns {
                Duration::from_nanos(target_ns - elapsed_ns)
            } else {
                Duration::ZERO
            }
        }

        ReplaySpeed::RealTime | ReplaySpeed::Multiplier(_) => {
            // Measure the gap from the first packet's timestamp, then scale.
            let first = *first_ts_ns.get_or_insert(pkt_ts_ns);
            let capture_gap_ns = pkt_ts_ns.saturating_sub(first);
            let scaled_gap_ns = match speed {
                ReplaySpeed::Multiplier(f) => (capture_gap_ns as f64 / f) as u64,
                _ => capture_gap_ns,
            };
            let elapsed_ns = start_time.elapsed().as_nanos() as u64;
            if scaled_gap_ns > elapsed_ns {
                Duration::from_nanos(scaled_gap_ns - elapsed_ns)
            } else {
                Duration::ZERO
            }
        }
    }
}

// ── Platform implementations ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use socket2::{Domain, Protocol, Socket, Type};

    use super::*;

    /// `AF_PACKET` address-family constant (Linux, all architectures).
    const AF_PACKET: i32 = 17;

    /// `ETH_P_ALL` in network byte order — required by `AF_PACKET` sockets.
    ///
    /// `htons(0x0003)` = `0x0300` = 768 on little-endian (the overwhelming
    /// majority of Linux systems). Computed portably with `to_be()`.
    const ETH_P_ALL_NBO: i32 = (0x0003_u16.to_be()) as i32;

    /// Mirror of `struct sockaddr_ll` from `<linux/if_packet.h>`.
    ///
    /// `AF_PACKET` bind requires this address structure; `socket2` has no
    /// built-in constructor for it, so we construct it directly.
    #[repr(C)]
    struct SockAddrLl {
        sll_family: u16,
        sll_protocol: u16,
        sll_ifindex: i32,
        sll_hatype: u16,
        sll_pkttype: u8,
        sll_halen: u8,
        sll_addr: [u8; 8],
    }

    /// Validate that `iface` is a plausible Linux interface name.
    ///
    /// Linux interface names are at most 15 bytes (`IFNAMSIZ - 1`) and in
    /// practice are limited to ASCII letters, digits, and a small set of
    /// punctuation. We reject anything outside `[A-Za-z0-9._-]` and disallow
    /// empty names, which also defends against path-traversal sequences like
    /// `../` being interpolated into the sysfs path below.
    pub(super) fn validate_iface_name(iface: &str) -> Result<(), ReplayError> {
        if iface.is_empty()
            || iface.len() > 15
            || !iface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ReplayError::InvalidInterface(iface.to_owned()));
        }
        Ok(())
    }

    /// Read the interface index from `/sys/class/net/<iface>/ifindex`.
    ///
    /// This avoids a `libc` dependency while remaining reliable on any
    /// Linux system (the sysfs entry is always present for real interfaces).
    fn read_ifindex(iface: &str) -> Result<i32, ReplayError> {
        validate_iface_name(iface)?;
        let path = format!("/sys/class/net/{iface}/ifindex");
        let s = std::fs::read_to_string(&path)
            .map_err(|_| ReplayError::UnknownInterface(iface.to_owned()))?;
        s.trim()
            .parse::<i32>()
            .map_err(|_| ReplayError::UnknownInterface(iface.to_owned()))
    }

    /// Open an `AF_PACKET / SOCK_RAW` socket and bind it to `iface`.
    fn open_raw_socket(iface: &str) -> Result<Socket, ReplayError> {
        let sock = Socket::new(
            Domain::from(AF_PACKET),
            Type::RAW,
            Some(Protocol::from(ETH_P_ALL_NBO)),
        )
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ReplayError::PermissionDenied(
                    "creating a raw AF_PACKET socket requires CAP_NET_RAW; \
                     run as root or: sudo setcap cap_net_raw+eip <binary>"
                        .to_owned(),
                )
            } else {
                ReplayError::Io(e)
            }
        })?;

        let ifindex = read_ifindex(iface)?;

        // Build sockaddr_ll and bind so that all outgoing packets use this NIC.
        // try_init returns (T, SockAddr) where T is the closure's Ok type.
        let (_, addr) = unsafe {
            socket2::SockAddr::try_init(|storage, len| {
                let sa = &mut *storage.cast::<SockAddrLl>();
                sa.sll_family = AF_PACKET as u16;
                sa.sll_protocol = 0x0003_u16.to_be(); // ETH_P_ALL in NBO
                sa.sll_ifindex = ifindex;
                sa.sll_hatype = 0;
                sa.sll_pkttype = 0;
                sa.sll_halen = 0;
                sa.sll_addr = [0u8; 8];
                *len = std::mem::size_of::<SockAddrLl>() as _;
                Ok(())
            })
        }
        .map_err(ReplayError::Io)?;

        sock.bind(&addr).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ReplayError::PermissionDenied("binding raw socket requires CAP_NET_RAW".to_owned())
            } else {
                ReplayError::Io(e)
            }
        })?;

        Ok(sock)
    }

    pub fn replay_impl(
        input: &PacketSource,
        opts: &ReplayOptions,
    ) -> Result<ReplayReport, ReplayError> {
        let sockets: Vec<Socket> = opts
            .interfaces
            .iter()
            .map(|iface| open_raw_socket(iface))
            .collect::<Result<_, _>>()?;

        let has_filter = !opts.filter.is_empty() || opts.bpf_filter.is_some();

        let iter = pcap::open_source_with_payload(input)
            .map_err(|e| ReplayError::PcapParse(e.to_string()))?;

        let mut packets_sent: u64 = 0;
        let mut bytes_sent: u64 = 0;
        let mut first_ts_ns: Option<u64> = None;
        let start_time = Instant::now();

        for result in iter {
            let pkt = result.map_err(|e| ReplayError::PcapParse(e.to_string()))?;

            if has_filter {
                let meta = PacketMeta::from_packet(
                    pkt.info.timestamp_ns,
                    pkt.info.captured_len,
                    &pkt.data,
                );
                let struct_pass = opts.filter.is_empty() || opts.filter.matches(&meta);
                let bpf_pass = opts
                    .bpf_filter
                    .as_ref()
                    .map(|b| b.eval(&meta))
                    .unwrap_or(true);
                if !struct_pass || !bpf_pass {
                    continue;
                }
            }

            let delay = compute_delay(
                &opts.speed,
                pkt.info.timestamp_ns,
                &mut first_ts_ns,
                packets_sent,
                &start_time,
            );
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }

            for sock in &sockets {
                sock.send(&pkt.data).map_err(ReplayError::Io)?;
            }
            packets_sent += 1;
            bytes_sent += pkt.data.len() as u64;
        }

        Ok(ReplayReport {
            packets_sent,
            bytes_sent,
        })
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    pub fn replay_impl(
        _input: &PacketSource,
        _opts: &ReplayOptions,
    ) -> Result<ReplayReport, ReplayError> {
        Err(ReplayError::NotSupported)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_speed_parse_max() {
        assert!(matches!(ReplaySpeed::parse("max"), Some(ReplaySpeed::Max)));
        assert!(matches!(ReplaySpeed::parse("MAX"), Some(ReplaySpeed::Max)));
        assert!(matches!(ReplaySpeed::parse("Max"), Some(ReplaySpeed::Max)));
    }

    #[test]
    fn test_replay_speed_parse_real_time() {
        assert!(matches!(
            ReplaySpeed::parse("1.0"),
            Some(ReplaySpeed::RealTime)
        ));
        assert!(matches!(
            ReplaySpeed::parse("1"),
            Some(ReplaySpeed::RealTime)
        ));
    }

    #[test]
    fn test_replay_speed_parse_multiplier() {
        assert!(matches!(
            ReplaySpeed::parse("2.0"),
            Some(ReplaySpeed::Multiplier(f)) if (f - 2.0).abs() < 1e-9
        ));
        assert!(matches!(
            ReplaySpeed::parse("0.5"),
            Some(ReplaySpeed::Multiplier(f)) if (f - 0.5).abs() < 1e-9
        ));
        assert!(matches!(
            ReplaySpeed::parse("10"),
            Some(ReplaySpeed::Multiplier(f)) if (f - 10.0).abs() < 1e-9
        ));
    }

    #[test]
    fn test_replay_speed_parse_invalid() {
        assert!(ReplaySpeed::parse("").is_none());
        assert!(ReplaySpeed::parse("abc").is_none());
        assert!(ReplaySpeed::parse("-1.0").is_none());
        assert!(ReplaySpeed::parse("0").is_none());
        assert!(ReplaySpeed::parse("0.0").is_none());
    }

    #[test]
    fn test_compute_delay_max_is_zero() {
        let mut first_ts = None;
        let start = Instant::now();
        let d = compute_delay(&ReplaySpeed::Max, 1_000_000_000, &mut first_ts, 0, &start);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn test_compute_delay_real_time_first_packet_is_zero() {
        let mut first_ts = None;
        let start = Instant::now();
        let d = compute_delay(
            &ReplaySpeed::RealTime,
            1_000_000_000,
            &mut first_ts,
            0,
            &start,
        );
        // First packet: gap = 0, so delay must be zero (or negligible).
        assert!(d < Duration::from_millis(10));
    }

    #[test]
    fn test_compute_delay_pps_first_packet_is_zero() {
        let mut first_ts = None;
        let start = Instant::now();
        // Packet 0 at 1000 pps: target = 0 * 1e9 / 1000 = 0 ns.
        let d = compute_delay(&ReplaySpeed::Pps(1000), 0, &mut first_ts, 0, &start);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn test_compute_delay_pps_zero_is_safe() {
        let mut first_ts = None;
        let start = Instant::now();
        let d = compute_delay(&ReplaySpeed::Pps(0), 0, &mut first_ts, 5, &start);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn test_compute_delay_pps_spacing() {
        // At 1 000 pps packet N should be sent 1 ms after packet 0.
        // We ask for delay just before the start so elapsed ≈ 0, meaning
        // the returned delay should equal the target offset.
        let mut first_ts = None;
        let start = Instant::now();
        // Packet 1: target = 1 * 1e9 / 1000 = 1_000_000 ns = 1 ms.
        let d = compute_delay(&ReplaySpeed::Pps(1_000), 0, &mut first_ts, 1, &start);
        assert!(
            d >= Duration::from_micros(990) && d <= Duration::from_millis(2),
            "expected ~1 ms delay, got {d:?}"
        );
    }

    #[test]
    fn test_compute_delay_pps_no_overflow_at_high_count() {
        // sent_count * 1_000_000_000 would overflow u64 at ~18.4 B.
        // At 10 Gpps this threshold is crossed after 18 seconds of replay.
        // Verify the result is still sane (positive, not wrapped).
        let pps: u64 = 10_000_000_000; // 10 Gpps
        let sent_count: u64 = 20_000_000_000; // 20 B packets — past the u64 overflow point
        let mut first_ts = None;
        let start = Instant::now();
        let d = compute_delay(&ReplaySpeed::Pps(pps), 0, &mut first_ts, sent_count, &start);
        // target_ns = 20e9 * 1e9 / 10e9 = 2_000_000_000 ns = 2 s
        // elapsed is ~0, so delay should be ~2 s and must not be zero (wrap sentinel).
        assert!(
            d >= Duration::from_millis(1_990),
            "delay wrapped or saturated: got {d:?}"
        );
    }

    #[test]
    fn test_compute_delay_pps_past_target_is_zero() {
        // If we are already past the target time, delay must be zero (no negative sleep).
        let mut first_ts = None;
        // Backdate start by 10 s so elapsed >> target.
        let start = Instant::now() - Duration::from_secs(10);
        // Packet 1 at 1 000 pps: target = 1 ms, but 10 s have elapsed.
        let d = compute_delay(&ReplaySpeed::Pps(1_000), 0, &mut first_ts, 1, &start);
        assert_eq!(d, Duration::ZERO);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_iface_name_accepts_normal_names() {
        use super::platform::validate_iface_name;
        for ok in ["eth0", "wlp3s0", "lo", "en-1", "br_lan.10", "veth0"] {
            assert!(validate_iface_name(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_iface_name_rejects_path_traversal_and_junk() {
        use super::platform::validate_iface_name;
        for bad in [
            "",                      // empty
            "../../etc/passwd",      // path-traversal
            "eth0/foo",              // slash
            "eth 0",                 // space
            "a".repeat(16).as_str(), // > IFNAMSIZ-1
            "wlan\n",                // newline
            "eth0\0",                // NUL
        ] {
            assert!(
                matches!(
                    validate_iface_name(bad),
                    Err(ReplayError::InvalidInterface(_))
                ),
                "should reject {bad:?}"
            );
        }
    }

    /// On Linux: verify that a nonexistent interface produces the right error.
    /// The test passes whether it fails at socket creation (PermissionDenied —
    /// no CAP_NET_RAW in CI) or at interface lookup (UnknownInterface).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_replay_unknown_interface_returns_error() {
        use crate::filter::Filter;

        let opts = ReplayOptions {
            interfaces: vec!["nonexistent_iface_xyz999".to_owned()],
            speed: ReplaySpeed::Max,
            filter: Filter::default(),
            bpf_filter: None,
        };

        // Build a minimal valid PCAP (header only, no packets).
        let mut pcap_bytes = Vec::new();
        pcap_bytes.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic
        pcap_bytes.extend_from_slice(&2u16.to_le_bytes()); // version major
        pcap_bytes.extend_from_slice(&4u16.to_le_bytes()); // version minor
        pcap_bytes.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        pcap_bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        pcap_bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        pcap_bytes.extend_from_slice(&1i32.to_le_bytes()); // network (Ethernet)

        let path = std::env::temp_dir().join("replay_test_no_iface.pcap");
        std::fs::write(&path, &pcap_bytes).unwrap();

        let err = replay_file(&path, &opts).unwrap_err();
        assert!(
            matches!(
                err,
                ReplayError::PermissionDenied(_) | ReplayError::UnknownInterface(_)
            ),
            "expected PermissionDenied or UnknownInterface, got: {err}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_replay_not_supported_on_non_linux() {
        use crate::filter::Filter;

        let opts = ReplayOptions {
            interfaces: vec!["eth0".to_owned()],
            speed: ReplaySpeed::RealTime,
            filter: Filter::default(),
            bpf_filter: None,
        };
        let path = std::path::Path::new("/dev/null");
        assert!(matches!(
            replay_file(path, &opts),
            Err(ReplayError::NotSupported)
        ));
    }
}
