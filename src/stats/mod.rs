//! Streaming statistics collection for PCAP captures.
//!
//! [`StatsCollector`] performs a single pass over packets, computing:
//! - capture start/end timestamps
//! - total packet and byte counts
//! - unique source and destination IPs
//! - per-flow packet/byte counts keyed by 5-tuple

pub mod flow;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, TimeZone, Utc};

pub use flow::FlowKey;

/// Per-flow statistics entry.
#[derive(Debug, Clone)]
pub struct FlowStats {
    /// 5-tuple key for this flow.
    pub key: FlowKey,
    /// Deterministic flow ID (bidirectional xxh3-style hash).
    pub flow_id: u64,
    /// Number of packets in this flow.
    pub packets: u64,
    /// Total bytes (captured length) in this flow.
    pub bytes: u64,
}

/// Aggregate statistics for an entire capture.
#[derive(Debug)]
pub struct CaptureInfo {
    /// Timestamp of the first packet.
    pub start: Option<DateTime<Utc>>,
    /// Timestamp of the last packet.
    pub end: Option<DateTime<Utc>>,
    /// Total number of packets.
    pub total_packets: u64,
    /// Total captured bytes (sum of captured lengths).
    pub total_bytes: u64,
    /// Unique source IP addresses observed.
    pub unique_src_ips: HashSet<IpAddr>,
    /// Unique destination IP addresses observed.
    pub unique_dst_ips: HashSet<IpAddr>,
    /// Per-flow statistics, ordered by insertion.
    pub flows: Vec<FlowStats>,
}

impl CaptureInfo {
    /// Return the number of unique flows observed.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Return the capture duration, or `None` if fewer than two packets were seen.
    pub fn duration(&self) -> Option<chrono::Duration> {
        match (self.start, self.end) {
            (Some(s), Some(e)) => Some(e - s),
            _ => None,
        }
    }
}

/// Incrementally accumulates capture statistics in a single streaming pass.
pub struct StatsCollector {
    unidirectional: bool,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
    total_packets: u64,
    total_bytes: u64,
    unique_src_ips: HashSet<IpAddr>,
    unique_dst_ips: HashSet<IpAddr>,
    /// Map from canonical [`FlowKey`] → (flow_id, packets, bytes). The key is
    /// canonicalised per [`FlowKey::canonical`], so bidirectional flows merge
    /// both directions under one entry.
    flow_map: HashMap<FlowKey, (u64, u64, u64)>,
}

impl StatsCollector {
    /// Create a new collector.
    ///
    /// Set `unidirectional = true` to compute direction-sensitive flow IDs.
    pub fn new(unidirectional: bool) -> Self {
        Self {
            unidirectional,
            start_ns: None,
            end_ns: None,
            total_packets: 0,
            total_bytes: 0,
            unique_src_ips: HashSet::new(),
            unique_dst_ips: HashSet::new(),
            flow_map: HashMap::new(),
        }
    }

    /// Feed one packet into the collector.
    ///
    /// - `timestamp_ns`: packet timestamp in nanoseconds since the Unix epoch.
    /// - `captured_len`: number of bytes captured for this packet.
    /// - `key`: optional parsed 5-tuple; `None` for non-IP packets (e.g. ARP).
    pub fn feed(&mut self, timestamp_ns: u64, captured_len: u32, key: Option<FlowKey>) {
        // Update time bounds.
        self.start_ns = Some(self.start_ns.map_or(timestamp_ns, |t| t.min(timestamp_ns)));
        self.end_ns = Some(self.end_ns.map_or(timestamp_ns, |t| t.max(timestamp_ns)));

        self.total_packets += 1;
        self.total_bytes += u64::from(captured_len);

        if let Some(ref k) = key {
            self.unique_src_ips.insert(k.src_ip);
            self.unique_dst_ips.insert(k.dst_ip);

            let flow_id = k.flow_id(self.unidirectional);
            // Group on the canonical key so that in bidirectional mode the two
            // directions of a conversation merge into a single flow; in
            // unidirectional mode the key is unchanged and directions stay split.
            let canon = k.canonical(self.unidirectional);
            let entry = self.flow_map.entry(canon).or_insert((flow_id, 0, 0));
            entry.1 += 1;
            entry.2 += u64::from(captured_len);
        }
    }

    /// Consume the collector and produce the final [`CaptureInfo`].
    pub fn finish(self) -> CaptureInfo {
        let start = self.start_ns.map(ns_to_datetime);
        let end = self.end_ns.map(ns_to_datetime);

        let flows = self
            .flow_map
            .into_iter()
            .map(|(key, (flow_id, packets, bytes))| FlowStats {
                key,
                flow_id,
                packets,
                bytes,
            })
            .collect();

        CaptureInfo {
            start,
            end,
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            unique_src_ips: self.unique_src_ips,
            unique_dst_ips: self.unique_dst_ips,
            flows,
        }
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
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn key(s: IpAddr, d: IpAddr, sp: u16, dp: u16, proto: u8) -> FlowKey {
        FlowKey::new(s, d, sp, dp, proto)
    }

    #[test]
    fn test_empty_collector_produces_zero_stats() {
        let info = StatsCollector::new(false).finish();
        assert_eq!(info.total_packets, 0);
        assert_eq!(info.total_bytes, 0);
        assert!(info.start.is_none());
        assert!(info.end.is_none());
        assert!(info.flows.is_empty());
    }

    #[test]
    fn test_single_packet_start_equals_end() {
        let mut col = StatsCollector::new(false);
        col.feed(1_000_000_000, 100, None);
        let info = col.finish();
        assert_eq!(info.total_packets, 1);
        assert_eq!(info.total_bytes, 100);
        assert_eq!(info.start, info.end);
        assert!(info.duration().unwrap().is_zero());
    }

    #[test]
    fn test_bidirectional_merges_both_directions_into_one_flow() {
        let mut col = StatsCollector::new(false);
        let k = key(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1000, 443, 6);
        col.feed(1_000_000_000, 100, Some(k.clone()));
        col.feed(2_000_000_000, 200, Some(k.clone()));
        // Reverse direction — same bidirectional flow, must merge.
        let rev = key(v4(10, 0, 0, 2), v4(10, 0, 0, 1), 443, 1000, 6);
        col.feed(3_000_000_000, 50, Some(rev));
        let info = col.finish();
        assert_eq!(info.total_packets, 3);
        assert_eq!(info.total_bytes, 350);
        // Forward + reverse collapse into a single bidirectional flow whose
        // packet/byte counts aggregate both directions.
        assert_eq!(info.flow_count(), 1);
        assert_eq!(info.flows[0].packets, 3);
        assert_eq!(info.flows[0].bytes, 350);
    }

    #[test]
    fn test_unidirectional_keeps_directions_separate() {
        let mut col = StatsCollector::new(true);
        let k = key(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1000, 443, 6);
        col.feed(1_000_000_000, 100, Some(k.clone()));
        col.feed(2_000_000_000, 200, Some(k));
        // Reverse direction — a distinct flow in unidirectional mode.
        let rev = key(v4(10, 0, 0, 2), v4(10, 0, 0, 1), 443, 1000, 6);
        col.feed(3_000_000_000, 50, Some(rev));
        let info = col.finish();
        assert_eq!(info.total_packets, 3);
        assert_eq!(info.total_bytes, 350);
        // Two directions → two separate flows, each with its own counts.
        assert_eq!(info.flow_count(), 2);
        let mut pkts: Vec<u64> = info.flows.iter().map(|f| f.packets).collect();
        pkts.sort_unstable();
        assert_eq!(pkts, vec![1, 2]);
    }

    #[test]
    fn test_unique_ips_tracked() {
        let mut col = StatsCollector::new(false);
        col.feed(
            1_000_000_000,
            60,
            Some(key(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 100, 80, 6)),
        );
        col.feed(
            2_000_000_000,
            60,
            Some(key(v4(1, 1, 1, 1), v4(3, 3, 3, 3), 100, 80, 6)),
        );
        let info = col.finish();
        assert_eq!(info.unique_src_ips.len(), 1);
        assert_eq!(info.unique_dst_ips.len(), 2);
    }
}
