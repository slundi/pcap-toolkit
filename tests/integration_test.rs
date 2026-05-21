//! Integration tests for the sort pipeline using hand-crafted PCAP byte buffers.

use std::io::Write;
use std::path::PathBuf;

use pcap_toolkit::bpf;
use pcap_toolkit::export::{ExportFormat, ExportOptions, export_file};
use pcap_toolkit::filter::{Filter, FilterRule, IpNet, Op, PortRange};
use pcap_toolkit::flow::FlowKey;
use pcap_toolkit::sort::{SortOptions, parse_slice, sort_file};
use pcap_toolkit::transform::{TransformOptions, parse_ip_mapping};

// ── PCAP builder helpers ─────────────────────────────────────────────────────

/// Write a legacy PCAP global header (24 bytes, LE, usec precision, Ethernet).
fn write_pcap_header(buf: &mut Vec<u8>, snaplen: u32) {
    buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic
    buf.extend_from_slice(&2u16.to_le_bytes()); // version major
    buf.extend_from_slice(&4u16.to_le_bytes()); // version minor
    buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&snaplen.to_le_bytes()); // snaplen
    buf.extend_from_slice(&1i32.to_le_bytes()); // network = LINKTYPE_ETHERNET
}

/// Append one legacy PCAP packet record (16-byte header + `data`).
fn write_pcap_packet(buf: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, data: &[u8]) {
    let caplen = data.len() as u32;
    buf.extend_from_slice(&ts_sec.to_le_bytes());
    buf.extend_from_slice(&ts_usec.to_le_bytes());
    buf.extend_from_slice(&caplen.to_le_bytes());
    buf.extend_from_slice(&caplen.to_le_bytes()); // origlen = caplen
    buf.extend_from_slice(data);
}

/// Build a minimal PCAP file with the given `(ts_sec, ts_usec, payload)` entries.
fn build_pcap(packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_pcap_header(&mut buf, 65535);
    for (sec, usec, data) in packets {
        write_pcap_packet(&mut buf, *sec, *usec, data);
    }
    buf
}

/// Write a PCAP buffer to a temp file and return its path.
fn write_tmp_pcap(name: &str, data: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(data).unwrap();
    path
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn test_sort_already_sorted_produces_identical_output() {
    let payload = vec![0xAAu8; 42];
    let pcap_data = build_pcap(&[
        (1000, 0, payload.clone()),
        (1001, 0, payload.clone()),
        (1002, 0, payload.clone()),
    ]);

    let input = write_tmp_pcap("sort_test_already_sorted_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("sort_test_already_sorted_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 3);
    assert_eq!(report.files_written.len(), 1);

    // Output file should be a valid PCAP with the magic header.
    let out_bytes = std::fs::read(&output).unwrap();
    assert_eq!(&out_bytes[0..4], &0xa1b2_c3d4u32.to_le_bytes());

    // 24 (global hdr) + 3 × (16 + 42) = 24 + 174 = 198 bytes
    assert_eq!(out_bytes.len(), 198);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_sort_out_of_order_reorders_packets() {
    // Packets arrive: T=3, T=1, T=2 — expect sorted output T=1, T=2, T=3.
    let make_payload = |id: u8| vec![id; 40];
    let pcap_data = build_pcap(&[
        (3, 0, make_payload(0x03)),
        (1, 0, make_payload(0x01)),
        (2, 0, make_payload(0x02)),
    ]);

    let input = write_tmp_pcap("sort_test_ooo_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("sort_test_ooo_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 3);

    // Verify first packet in output has ts_sec = 1.
    let out_bytes = std::fs::read(&output).unwrap();
    let first_ts_sec = u32::from_le_bytes(out_bytes[24..28].try_into().unwrap());
    assert_eq!(first_ts_sec, 1);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_sort_on_disk_index_produces_same_result() {
    let payload = vec![0xBBu8; 60];
    let pcap_data = build_pcap(&[
        (5, 0, payload.clone()),
        (3, 0, payload.clone()),
        (4, 0, payload.clone()),
    ]);

    let input = write_tmp_pcap("sort_test_disk_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("sort_test_disk_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        on_disk: true,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 3);

    // Sidecar file should be cleaned up.
    let sidecar = pcap_toolkit::sort::index::sidecar_path(&input);
    assert!(
        !sidecar.exists(),
        "sidecar file should be removed after sort"
    );

    let out_bytes = std::fs::read(&output).unwrap();
    let first_ts_sec = u32::from_le_bytes(out_bytes[24..28].try_into().unwrap());
    assert_eq!(first_ts_sec, 3);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_sort_with_time_slice() {
    let payload = vec![0xCCu8; 20];
    // Three packets: two in hour 0, one in hour 1.
    let pcap_data = build_pcap(&[
        (0, 0, payload.clone()),    // T = 0s     → slice 0
        (1800, 0, payload.clone()), // T = 1800s  → slice 0
        (3601, 0, payload.clone()), // T = 3601s  → slice 1
    ]);

    let input = write_tmp_pcap("sort_test_slice_in.pcap", &pcap_data);
    let out_dir = std::env::temp_dir().join("pcap_sort_slice_out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let opts = SortOptions {
        output: out_dir.clone(),
        slice_secs: Some(3600),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 3);
    assert_eq!(report.files_written.len(), 2, "expected two slice files");

    // Each output file must start with the PCAP magic.
    for f in &report.files_written {
        let bytes = std::fs::read(f).unwrap();
        assert_eq!(&bytes[0..4], &0xa1b2_c3d4u32.to_le_bytes());
        let _ = std::fs::remove_file(f);
    }

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir(&out_dir);
}

#[test]
fn test_sort_empty_pcap() {
    let pcap_data = build_pcap(&[]);

    let input = write_tmp_pcap("sort_test_empty_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("sort_test_empty_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 0);
    assert_eq!(report.files_written.len(), 0);

    let _ = std::fs::remove_file(&input);
    // No output file created for empty input.
}

// ── Ethernet+IPv4 frame builders ─────────────────────────────────────────────

/// Build a minimal valid Ethernet + IPv4 + UDP frame (42 bytes).
///
/// Checksums are zeroed — etherparse does not validate them on read.
fn eth_ipv4_udp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut frame = Vec::with_capacity(14 + 20 + 8 + payload.len());
    // Ethernet header (14 bytes): dst MAC, src MAC, EtherType=0x0800
    frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header (20 bytes)
    frame.push(0x45); // version=4, IHL=5
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]); // ID
    frame.extend_from_slice(&[0x00, 0x00]); // flags/offset
    frame.push(64); // TTL
    frame.push(17); // protocol = UDP
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (zeroed)
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    // UDP header (8 bytes)
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // checksum
    frame.extend_from_slice(payload);
    frame
}

/// Build a minimal valid Ethernet + IPv4 + TCP frame.
fn eth_ipv4_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + 20 + payload.len()) as u16;
    let mut frame = Vec::with_capacity(14 + 20 + 20 + payload.len());
    // Ethernet
    frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.push(64);
    frame.push(6); // TCP
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    // TCP header (20 bytes)
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    frame.push(0x50); // data offset = 5 (20 bytes), reserved = 0
    frame.push(tcp_flags); // flags
    frame.extend_from_slice(&[0xff, 0xff]); // window
    frame.extend_from_slice(&[0x00, 0x00]); // checksum
    frame.extend_from_slice(&[0x00, 0x00]); // urgent
    frame.extend_from_slice(payload);
    frame
}

// ── Filter integration tests ─────────────────────────────────────────────────

#[test]
fn test_filter_by_protocol_keeps_udp_only() {
    let udp_frame = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, &[0u8; 8]);
    let tcp_frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5678, 443, 0x02, &[0u8; 4]);

    let pcap_data = build_pcap(&[
        (1, 0, udp_frame.clone()),
        (2, 0, tcp_frame.clone()),
        (3, 0, udp_frame.clone()),
    ]);
    let input = write_tmp_pcap("filter_proto_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_proto_out.pcap");

    let mut filter = Filter::default();
    filter.protocols = vec![17]; // UDP only

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 2, "only UDP packets should pass");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_filter_by_src_ip_cidr() {
    let inside = eth_ipv4_udp([10, 0, 0, 5], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);
    let outside = eth_ipv4_udp([192, 168, 1, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);

    let pcap_data = build_pcap(&[(1, 0, inside), (2, 0, outside)]);
    let input = write_tmp_pcap("filter_srcip_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_srcip_out.pcap");

    let mut filter = Filter::default();
    filter.src_ips = vec![IpNet::parse("10.0.0.0/8").unwrap()];

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 1);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_filter_by_dst_port() {
    let https = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5000, 443, 0x10, &[0u8; 4]);
    let http = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5001, 80, 0x10, &[0u8; 4]);
    let dns = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 5002, 53, &[0u8; 4]);

    let pcap_data = build_pcap(&[(1, 0, https), (2, 0, http), (3, 0, dns)]);
    let input = write_tmp_pcap("filter_dport_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_dport_out.pcap");

    let mut filter = Filter::default();
    filter.dst_ports = vec![PortRange {
        start: 443,
        end: 443,
    }];

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 1,
        "only port-443 TCP packet should pass"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_filter_by_time_range() {
    let frame = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 1, 2, &[0u8; 4]);
    // Packets at T=1s, T=5s, T=10s — keep only T=5s (within [4s, 6s]).
    let pcap_data = build_pcap(&[
        (1, 0, frame.clone()),
        (5, 0, frame.clone()),
        (10, 0, frame.clone()),
    ]);
    let input = write_tmp_pcap("filter_time_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_time_out.pcap");

    let mut filter = Filter::default();
    filter.from_ns = Some(4_000_000_000); // 4s in ns
    filter.to_ns = Some(6_000_000_000); // 6s in ns

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 1);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_filter_by_flow_id() {
    use std::net::IpAddr;
    let frame_a = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 443, 0x02, &[0u8; 4]);
    let frame_b = eth_ipv4_tcp([10, 0, 0, 3], [10, 0, 0, 4], 5678, 80, 0x02, &[0u8; 4]);

    // Pre-compute flow ID for the first flow.
    let key = FlowKey::new(
        IpAddr::from([10, 0, 0, 1]),
        IpAddr::from([10, 0, 0, 2]),
        1234,
        443,
        6,
    );
    let flow_id = key.flow_id(false);

    let pcap_data = build_pcap(&[(1, 0, frame_a), (2, 0, frame_b)]);
    let input = write_tmp_pcap("filter_flowid_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_flowid_out.pcap");

    let mut filter = Filter::default();
    filter.flow_ids = vec![flow_id];

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 1, "only flow A should pass");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_filter_empty_output_when_nothing_matches() {
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);
    let pcap_data = build_pcap(&[(1, 0, frame.clone()), (2, 0, frame)]);
    let input = write_tmp_pcap("filter_none_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_none_out.pcap");

    let mut filter = Filter::default();
    filter.protocols = vec![6]; // TCP only; all packets are UDP → nothing passes

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 0);
    assert!(report.files_written.is_empty());

    let _ = std::fs::remove_file(&input);
}

#[test]
fn test_filter_negate_inverts_result() {
    // Base filter: TCP only. With negate=true, should keep everything that is NOT TCP.
    let tcp_frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02, &[0u8; 4]);
    let udp_frame = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, &[0u8; 4]);

    let pcap_data = build_pcap(&[(1, 0, tcp_frame), (2, 0, udp_frame)]);
    let input = write_tmp_pcap("filter_negate_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_negate_out.pcap");

    let mut filter = Filter::default();
    filter.protocols = vec![6]; // TCP only
    filter.negate = true; // invert: keep non-TCP

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 1,
        "only non-TCP (UDP) packet should pass"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_filter_or_rule_chain() {
    // Base filter: TCP only.
    // OR rule: UDP proto.
    // Result: packets matching TCP OR UDP should both pass.
    let tcp_frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02, &[0u8; 4]);
    let udp_frame = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, &[0u8; 4]);

    let pcap_data = build_pcap(&[(1, 0, tcp_frame), (2, 0, udp_frame)]);
    let input = write_tmp_pcap("filter_or_rule_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_or_rule_out.pcap");

    let mut filter = Filter::default();
    filter.protocols = vec![6]; // base: TCP only
    let mut udp_rule = FilterRule::default();
    udp_rule.op = Op::Or;
    udp_rule.protocols = vec![17]; // OR UDP
    filter.rules = vec![udp_rule];

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 2,
        "TCP and UDP packets should both pass"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_filter_not_rule_excludes_subset() {
    // Base filter: matches all packets (empty).
    // NOT rule: exclude packets with dst_port=80.
    // Only non-port-80 packet should pass.
    let http = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x02, &[0u8; 4]);
    let https = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5001, 443, 0x02, &[0u8; 4]);

    let pcap_data = build_pcap(&[(1, 0, http), (2, 0, https)]);
    let input = write_tmp_pcap("filter_not_rule_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("filter_not_rule_out.pcap");

    let mut filter = Filter::default();
    let mut exclude_rule = FilterRule::default();
    exclude_rule.op = Op::Not;
    exclude_rule.dst_ports = vec![PortRange { start: 80, end: 80 }];
    filter.rules = vec![exclude_rule];

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 1,
        "only the non-port-80 packet should pass"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_bpf_filter_tcp_and_dst_port() {
    let tcp443 = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5000, 443, 0x02, &[0u8; 4]);
    let tcp80 = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5001, 80, 0x02, &[0u8; 4]);
    let udp = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 5002, 443, &[0u8; 4]);

    let pcap_data = build_pcap(&[(1, 0, tcp443), (2, 0, tcp80), (3, 0, udp)]);
    let input = write_tmp_pcap("bpf_tcp_dport_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_tcp_dport_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("tcp and dst port 443").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 1,
        "only TCP dst-port-443 should pass"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_bpf_filter_combined_with_structured() {
    // Structured filter: src IP 10.0.0.0/8
    // BPF filter: "dst port 443"
    // Only the TCP/443 packet from 10.x should pass both.
    let tcp443_inside = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5000, 443, 0x02, &[0u8; 4]);
    let tcp443_outside = eth_ipv4_tcp([1, 2, 3, 4], [8, 8, 8, 8], 5001, 443, 0x02, &[0u8; 4]);
    let tcp80_inside = eth_ipv4_tcp([10, 0, 0, 2], [8, 8, 8, 8], 5002, 80, 0x02, &[0u8; 4]);

    let pcap_data = build_pcap(&[
        (1, 0, tcp443_inside),
        (2, 0, tcp443_outside),
        (3, 0, tcp80_inside),
    ]);
    let input = write_tmp_pcap("bpf_combined_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_combined_out.pcap");

    let mut filter = Filter::default();
    filter.src_ips = vec![IpNet::parse("10.0.0.0/8").unwrap()];

    let opts = SortOptions {
        output: output.clone(),
        filter,
        bpf_filter: Some(bpf::parse("dst port 443").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 1,
        "only 10.x→443 packet passes both filters"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

// ── Transform integration tests ───────────────────────────────────────────────

#[test]
fn test_transform_payload_truncation_reduces_output_size() {
    // Packets with 100-byte payloads; truncate to 10 bytes.
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0xAA; 100]);
    let full_frame_len = frame.len(); // 14 + 20 + 8 + 100 = 142
    let pcap_data = build_pcap(&[(1, 0, frame.clone()), (2, 0, frame)]);

    let input = write_tmp_pcap("transform_trunc_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("transform_trunc_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        transform: TransformOptions {
            max_payload_bytes: Some(10),
            ..Default::default()
        },
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 2);

    let out_bytes = std::fs::read(&output).unwrap();
    // Expected: 24 (global hdr) + 2 × (16 + 52) = 24 + 136 = 160
    // where 52 = 14 + 20 + 8 + 10
    let truncated_frame_len = 14 + 20 + 8 + 10;
    assert!(
        full_frame_len > truncated_frame_len,
        "original frame was not larger than truncated"
    );
    assert_eq!(out_bytes.len(), 24 + 2 * (16 + truncated_frame_len));

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_transform_ip_mapping_rewrites_address_in_output() {
    let frame = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5000, 443, 0x02, &[0u8; 4]);
    let pcap_data = build_pcap(&[(1, 0, frame)]);

    let input = write_tmp_pcap("transform_ipmap_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("transform_ipmap_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        transform: TransformOptions {
            ip_map: vec![parse_ip_mapping("10.0.0.1=192.168.99.1").unwrap()],
            ..Default::default()
        },
        ..SortOptions::default()
    };
    sort_file(&input, &opts).unwrap();

    let out_bytes = std::fs::read(&output).unwrap();
    // The first packet's data starts at byte 40 (24 global hdr + 16 pkt hdr).
    // IPv4 src IP is at Ethernet(14) + IPv4 src offset(12) = byte 26 within the frame.
    // In the output file: 40 + 26 = byte 66.
    let ip_src = &out_bytes[66..70];
    assert_eq!(ip_src, &[192, 168, 99, 1], "src IP should be rewritten");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_transform_timestamp_shift_moves_first_packet() {
    // Two packets at T=10s and T=12s.
    // Shift so first starts at T=1000s.
    let frame = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &[0u8; 4]);
    let pcap_data = build_pcap(&[(10, 0, frame.clone()), (12, 0, frame)]);

    let input = write_tmp_pcap("transform_tsshift_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("transform_tsshift_out.pcap");

    // Target start = 1000s in nanoseconds.
    let target_ns: u64 = 1000 * 1_000_000_000;
    let opts = SortOptions {
        output: output.clone(),
        transform: TransformOptions {
            timestamp_start_ns: Some(target_ns),
            ..Default::default()
        },
        ..SortOptions::default()
    };
    sort_file(&input, &opts).unwrap();

    let out_bytes = std::fs::read(&output).unwrap();
    // First packet record starts at byte 24; ts_sec is the first 4 bytes.
    let first_ts_sec = u32::from_le_bytes(out_bytes[24..28].try_into().unwrap());
    assert_eq!(first_ts_sec, 1000, "first packet should start at T=1000s");

    // Second packet should be at T=1002s (original gap was 2s).
    // Output record starts at 24 + 16 + frame_len.
    let frame_len = 14 + 20 + 8 + 4; // 46
    let second_pkt_off = 24 + 16 + frame_len;
    let second_ts_sec = u32::from_le_bytes(
        out_bytes[second_pkt_off..second_pkt_off + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        second_ts_sec, 1002,
        "second packet should be 2s after first"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_parse_slice_values() {
    assert_eq!(parse_slice("1h").unwrap(), 3600);
    assert_eq!(parse_slice("30m").unwrap(), 1800);
    assert_eq!(parse_slice("2d").unwrap(), 172800);
    assert_eq!(parse_slice("60s").unwrap(), 60);
    assert_eq!(parse_slice("300").unwrap(), 300);
    assert!(parse_slice("bad").is_err());
}

// ── Export integration tests ──────────────────────────────────────────────────

#[test]
fn test_export_json_packet_count() {
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 8]);
    let pcap_data = build_pcap(&[
        (1000, 0, frame.clone()),
        (1001, 0, frame.clone()),
        (1002, 0, frame),
    ]);
    let input = write_tmp_pcap("export_json_count_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_count_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 3);
    assert!(output.exists());

    // Verify the file contains exactly 3 lines (one JSON object per packet).
    let content = std::fs::read_to_string(&output).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3);

    // Each line must parse as valid JSON and contain timestamp_ns.
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("line must be valid JSON");
        assert!(v["timestamp_ns"].is_number());
        assert_eq!(v["src_ip"], "10.0.0.1");
        assert_eq!(v["dst_ip"], "8.8.8.8");
        assert_eq!(v["src_port"], 1234);
        assert_eq!(v["dst_port"], 53);
        assert_eq!(v["protocol"], 17); // UDP
        assert!(v["flow_id"].is_string());
        assert!(v["payload"].is_string()); // base64-encoded
        assert_eq!(v["payload_encoding"], "base64");
    }

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_json_timestamps_correct() {
    let frame = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &[]);
    let pcap_data = build_pcap(&[(2000, 500_000, frame.clone()), (2001, 0, frame)]);
    let input = write_tmp_pcap("export_json_ts_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_ts_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let mut lines = content.lines();

    // ts_sec=2000, ts_usec=500000 → 2000*1e9 + 500000*1000 = 2_000_500_000_000
    let v0: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(v0["timestamp_ns"], 2_000_500_000_000u64);

    let v1: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(v1["timestamp_ns"], 2_001_000_000_000u64);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_json_tcp_flags_present() {
    // SYN packet (flags = 0x02)
    let frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443, 0x02, &[]);
    let pcap_data = build_pcap(&[(1, 0, frame)]);
    let input = write_tmp_pcap("export_json_flags_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_flags_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(v["protocol"], 6); // TCP
    assert_eq!(v["tcp_flags"], 0x02); // SYN

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_json_non_ip_frame_no_flow_fields() {
    // Raw ARP-like frame (no IP layer): etherparse returns no flow_key.
    let raw = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x06, // EtherType = ARP
        0x00, 0x01, // hardware type
        0x08, 0x00, // protocol type
        0x06, 0x04, // hw/proto size
        0x00, 0x01, // ARP request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender hw addr
        0x0a, 0x00, 0x00, 0x01, // sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target hw addr
        0x0a, 0x00, 0x00, 0x02, // target IP
    ];
    let pcap_data = build_pcap(&[(1, 0, raw)]);
    let input = write_tmp_pcap("export_json_arp_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_arp_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    // IP-layer fields must be absent.
    assert!(v["src_ip"].is_null());
    assert!(v["dst_ip"].is_null());
    assert!(v["flow_id"].is_null());
    assert_eq!(v["caplen"], 42);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_json_with_filter() {
    let udp_frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);
    let tcp_frame = eth_ipv4_tcp([10, 0, 0, 2], [1, 1, 1, 1], 5000, 80, 0x02, &[0u8; 4]);
    let pcap_data = build_pcap(&[
        (1, 0, udp_frame),
        (2, 0, tcp_frame.clone()),
        (3, 0, tcp_frame),
    ]);
    let input = write_tmp_pcap("export_json_filter_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_filter_out.jsonl");

    // Keep only TCP packets.
    let mut filter = Filter::default();
    filter.protocols = vec![6]; // TCP

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        filter,
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 2);

    let content = std::fs::read_to_string(&output).unwrap();
    assert_eq!(content.lines().count(), 2);
    for line in content.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["protocol"], 6);
    }

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_json_compress_payload() {
    let frame = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200, &[0xAA; 32]);
    let pcap_data = build_pcap(&[(1, 0, frame)]);
    let input = write_tmp_pcap("export_json_zstd_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_zstd_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        compress_payload: true,
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(v["payload_encoding"], "zstd+base64");
    // The payload field must be a non-empty string.
    assert!(v["payload"].as_str().is_some_and(|s| !s.is_empty()));

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_parquet_creates_file() {
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 8]);
    let pcap_data = build_pcap(&[(1, 0, frame.clone()), (2, 0, frame)]);
    let input = write_tmp_pcap("export_parquet_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_parquet_out.parquet");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Parquet),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 2);
    assert!(output.exists());
    // Verify the Parquet magic bytes ("PAR1") are present at start and end.
    let bytes = std::fs::read(&output).unwrap();
    assert!(bytes.len() >= 8);
    assert_eq!(&bytes[..4], b"PAR1");
    assert_eq!(&bytes[bytes.len() - 4..], b"PAR1");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_avro_creates_file_and_schema() {
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 4]);
    let pcap_data = build_pcap(&[(1, 0, frame)]);
    let input = write_tmp_pcap("export_avro_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_avro_out.avro");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Avro),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 1);
    assert!(output.exists());

    // Avro magic: "Obj\x01" at start.
    let bytes = std::fs::read(&output).unwrap();
    assert!(bytes.len() >= 4);
    assert_eq!(&bytes[..4], b"Obj\x01");

    // Schema sidecar must exist.
    let schema_path = output.with_extension("avsc");
    assert!(schema_path.exists());
    // Schema file must be valid JSON.
    let schema_text = std::fs::read_to_string(&schema_path).unwrap();
    serde_json::from_str::<serde_json::Value>(&schema_text).expect("avsc must be valid JSON");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(output.with_extension("avsc"));
}

#[test]
fn test_export_format_inferred_from_extension() {
    assert_eq!(
        ExportFormat::from_extension(std::path::Path::new("out.jsonl")),
        Some(ExportFormat::Json)
    );
    assert_eq!(
        ExportFormat::from_extension(std::path::Path::new("out.parquet")),
        Some(ExportFormat::Parquet)
    );
    assert_eq!(
        ExportFormat::from_extension(std::path::Path::new("out.avro")),
        Some(ExportFormat::Avro)
    );
    assert_eq!(
        ExportFormat::from_extension(std::path::Path::new("out.pcap")),
        None
    );
}

#[test]
fn test_export_json_empty_pcap_produces_empty_file() {
    let pcap_data = build_pcap(&[]);
    let input = write_tmp_pcap("export_json_empty_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_empty_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 0);
    assert!(output.exists());
    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.is_empty());

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}
