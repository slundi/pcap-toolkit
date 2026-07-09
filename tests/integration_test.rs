//! Integration tests: hand-crafted PCAP buffers and committed fixture files.

use std::io::Write;
use std::path::PathBuf;

use pcap_toolkit::bpf;
use pcap_toolkit::export::{
    ExportFormat, ExportOptions, MultiExportOptions, OutputDest, OutputTarget, export_file,
    export_multi,
};
use pcap_toolkit::filter::{Filter, FilterRule, IpNet, Op, PortRange};
use pcap_toolkit::flow::FlowKey;
use pcap_toolkit::pcap::count_flows_in_file;
use pcap_toolkit::sort::{SortOptions, parse_slice, sort_file, sort_files};
use pcap_toolkit::transform::{TransformOptions, parse_ip_mapping};
use rustc_hash::FxHashSet;

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

    let filter = Filter {
        protocols: vec![17], // UDP only
        ..Default::default()
    };

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

    let filter = Filter {
        src_ips: vec![IpNet::parse("10.0.0.0/8").unwrap()],
        ..Default::default()
    };

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

    let filter = Filter {
        dst_ports: vec![PortRange {
            start: 443,
            end: 443,
        }],
        ..Default::default()
    };

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

    let filter = Filter {
        from_ns: Some(4_000_000_000), // 4s in ns
        to_ns: Some(6_000_000_000),   // 6s in ns
        ..Default::default()
    };

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

    let filter = Filter {
        flow_ids: [flow_id].into_iter().collect(),
        ..Default::default()
    };

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

    let filter = Filter {
        protocols: vec![6], // TCP only; all packets are UDP → nothing passes
        ..Default::default()
    };

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

    let filter = Filter {
        protocols: vec![6], // TCP only
        negate: true,       // invert: keep non-TCP
        ..Default::default()
    };

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

    let filter = Filter {
        protocols: vec![6], // base: TCP only
        rules: vec![FilterRule {
            op: Op::Or,
            protocols: vec![17], // OR UDP
            ..Default::default()
        }],
        ..Default::default()
    };

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

    let filter = Filter {
        rules: vec![FilterRule {
            op: Op::Not,
            dst_ports: vec![PortRange { start: 80, end: 80 }],
            ..Default::default()
        }],
        ..Default::default()
    };

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

    let filter = Filter {
        src_ips: vec![IpNet::parse("10.0.0.0/8").unwrap()],
        ..Default::default()
    };

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

// ── Multi-file parallel sort tests (7.2) ─────────────────────────────────────

#[test]
fn test_sort_files_merges_two_files_in_timestamp_order() {
    // File A: packets at T=1s, T=3s, T=5s
    // File B: packets at T=2s, T=4s, T=6s
    // Expected merged output: T=1,2,3,4,5,6
    let make_payload = |id: u8| vec![id; 40];
    let pcap_a = build_pcap(&[
        (1, 0, make_payload(0x01)),
        (3, 0, make_payload(0x03)),
        (5, 0, make_payload(0x05)),
    ]);
    let pcap_b = build_pcap(&[
        (2, 0, make_payload(0x02)),
        (4, 0, make_payload(0x04)),
        (6, 0, make_payload(0x06)),
    ]);

    let input_a = write_tmp_pcap("sort_files_a.pcap", &pcap_a);
    let input_b = write_tmp_pcap("sort_files_b.pcap", &pcap_b);
    let output = std::env::temp_dir().join("sort_files_merged.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_files(&[input_a.as_path(), input_b.as_path()], &opts).unwrap();

    assert_eq!(report.packets_written, 6);
    assert_eq!(report.files_written.len(), 1);

    let out_bytes = std::fs::read(&output).unwrap();
    // Verify the first packet has ts_sec = 1.
    let first_ts = u32::from_le_bytes(out_bytes[24..28].try_into().unwrap());
    assert_eq!(first_ts, 1);
    // Verify the last packet's ts_sec.  Offset: 24 + 5*(16+40) = 24 + 280 = 304
    let last_pkt_off = 24 + 5 * (16 + 40);
    let last_ts = u32::from_le_bytes(
        out_bytes[last_pkt_off..last_pkt_off + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(last_ts, 6);

    let _ = std::fs::remove_file(&input_a);
    let _ = std::fs::remove_file(&input_b);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_sort_files_single_input_matches_sort_file() {
    // sort_files with one input must produce the same result as sort_file.
    let payload = vec![0xBBu8; 30];
    let pcap_data = build_pcap(&[
        (5, 0, payload.clone()),
        (2, 0, payload.clone()),
        (8, 0, payload.clone()),
    ]);
    let input = write_tmp_pcap("sort_files_single.pcap", &pcap_data);
    let output = std::env::temp_dir().join("sort_files_single_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_files(&[input.as_path()], &opts).unwrap();
    assert_eq!(report.packets_written, 3);

    let out_bytes = std::fs::read(&output).unwrap();
    let first_ts = u32::from_le_bytes(out_bytes[24..28].try_into().unwrap());
    assert_eq!(first_ts, 2);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

// ── First-pass pre-filter tests (7.4) ────────────────────────────────────────

#[test]
fn test_first_pass_prefilter_reduces_output_count() {
    // Pre-filter: TCP only. Two TCP packets + one UDP packet.
    // The UDP packet should be skipped at index time (first pass) and
    // never appear in the output.
    let tcp_frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02, &[0u8; 4]);
    let udp_frame = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, &[0u8; 4]);

    let pcap_data = build_pcap(&[
        (1, 0, tcp_frame.clone()),
        (2, 0, udp_frame),
        (3, 0, tcp_frame),
    ]);
    let input = write_tmp_pcap("prefilter_proto_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("prefilter_proto_out.pcap");

    let filter = Filter {
        protocols: vec![6], // TCP only
        ..Default::default()
    };

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 2, "only TCP packets should appear");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_first_pass_prefilter_with_bpf() {
    // BPF filter: "dst port 443". Three packets: two TCP/443, one TCP/80.
    let tcp443 = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5000, 443, 0x02, &[0u8; 4]);
    let tcp80 = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5001, 80, 0x02, &[0u8; 4]);

    let pcap_data = build_pcap(&[(1, 0, tcp443.clone()), (2, 0, tcp80), (3, 0, tcp443)]);
    let input = write_tmp_pcap("prefilter_bpf_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("prefilter_bpf_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("dst port 443").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 2,
        "only dst-port-443 packets should appear"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
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
        assert!(
            v["flow_id"].is_u64() || v["flow_id"].is_i64(),
            "flow_id must be a numeric u64"
        );
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
    let filter = Filter {
        protocols: vec![6], // TCP
        ..Default::default()
    };

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

// ── Flow count threshold filter tests ────────────────────────────────────────

/// `count_flows_in_file` returns the correct packet count per flow.
#[test]
fn test_count_flows_returns_counts_per_flow() {
    // Flow A: 10.0.0.1:1000 → 10.0.0.2:80 (UDP, 3 packets)
    // Flow B: 10.0.0.3:2000 → 10.0.0.4:443 (UDP, 1 packet)
    let fa = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, &[]);
    let fb = eth_ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 2000, 443, &[]);
    let pcap_data = build_pcap(&[
        (1, 0, fa.clone()),
        (2, 0, fa.clone()),
        (3, 0, fa.clone()),
        (4, 0, fb.clone()),
    ]);
    let input = write_tmp_pcap("count_flows_basic.pcap", &pcap_data);

    let counts = count_flows_in_file(&input, &Filter::default(), None, false).unwrap();
    // Two distinct 5-tuples → two distinct bidirectional flow IDs.
    assert_eq!(counts.len(), 2);
    let total: u64 = counts.values().sum();
    assert_eq!(total, 4);

    let _ = std::fs::remove_file(&input);
}

/// `count_flows_in_file` correctly counts per flow (each unidirectional flow separate).
#[test]
fn test_count_flows_basic() {
    // Flow A: 3 packets; Flow B: 1 packet. Unidirectional → 2 distinct flow IDs.
    let fa = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, &[]);
    let fb = eth_ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 2000, 443, &[]);
    let pcap_data = build_pcap(&[
        (1, 0, fa.clone()),
        (2, 0, fa.clone()),
        (3, 0, fa.clone()),
        (4, 0, fb.clone()),
    ]);
    let input = write_tmp_pcap("count_flows_unidirectional.pcap", &pcap_data);

    let counts = count_flows_in_file(&input, &Filter::default(), None, true).unwrap();
    assert_eq!(counts.len(), 2);
    let max_count = *counts.values().max().unwrap();
    let min_count = *counts.values().min().unwrap();
    assert_eq!(max_count, 3);
    assert_eq!(min_count, 1);

    let _ = std::fs::remove_file(&input);
}

/// `count_flows_in_file` applies the structured filter before counting.
#[test]
fn test_count_flows_respects_filter() {
    // Two flows: TCP and UDP. Filter to TCP only → only 1 flow counted.
    let tcp_pkt = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x02, &[]);
    let udp_pkt = eth_ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 5001, 53, &[]);
    let pcap_data = build_pcap(&[
        (1, 0, tcp_pkt.clone()),
        (2, 0, tcp_pkt.clone()),
        (3, 0, udp_pkt.clone()),
    ]);
    let input = write_tmp_pcap("count_flows_filter.pcap", &pcap_data);

    let filter = Filter {
        protocols: vec![6], // TCP only
        ..Default::default()
    };
    let counts = count_flows_in_file(&input, &filter, None, true).unwrap();
    // Only the TCP flow should be counted.
    assert_eq!(counts.len(), 1);
    let total: u64 = counts.values().sum();
    assert_eq!(total, 2);

    let _ = std::fs::remove_file(&input);
}

/// Sort with `min_flow_packets` excludes single-packet flows.
#[test]
fn test_sort_min_flow_packets_excludes_low_count_flows() {
    // Flow A: 3 packets (should survive threshold ≥ 2).
    // Flow B: 1 packet (should be dropped).
    let fa = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, &[0u8; 10]);
    let fb = eth_ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 2000, 443, &[0u8; 10]);
    let pcap_data = build_pcap(&[
        (1, 0, fa.clone()),
        (2, 0, fa.clone()),
        (3, 0, fa.clone()),
        (4, 0, fb.clone()),
    ]);
    let input = write_tmp_pcap("min_flow_sort_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("min_flow_sort_out.pcap");

    // Pre-scan to resolve qualifying flow IDs (threshold = 2).
    let filter = Filter::default();
    let counts = count_flows_in_file(&input, &filter, None, true).unwrap();
    let qualifying: FxHashSet<u64> = counts
        .into_iter()
        .filter(|(_, c)| *c >= 2)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(qualifying.len(), 1, "only flow A should qualify");

    let mut effective_filter = filter;
    effective_filter.flow_ids = qualifying;
    effective_filter.unidirectional = true;

    let opts = SortOptions {
        output: output.clone(),
        filter: effective_filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 3,
        "only the 3 packets of flow A written"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

// ── --format / multi-output fan-out tests (#8) ───────────────────────────────

/// Fan-out export writes each output in the correct format regardless of which
/// target receives an explicit format and which infers it from its extension.
/// This exercises the documented behaviour of `--format`: it applies only to
/// the first `--output`; subsequent outputs resolve their format from their
/// file extension.
#[test]
fn test_export_multi_fanout_writes_correct_formats() {
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0u8; 8]);
    let pcap_data = build_pcap(&[
        (1000, 0, frame.clone()),
        (1001, 0, frame.clone()),
        (1002, 0, frame),
    ]);
    let input = write_tmp_pcap("multi_fanout_in.pcap", &pcap_data);
    let out_json = std::env::temp_dir().join("multi_fanout_out.jsonl");
    let out_parquet = std::env::temp_dir().join("multi_fanout_out.parquet");

    let opts = MultiExportOptions {
        targets: vec![
            // First target: format supplied explicitly (mirrors --format on the CLI).
            OutputTarget {
                dest: OutputDest::File(out_json.clone()),
                format: Some(ExportFormat::Json),
                compress_payload: false,
            },
            // Second target: format inferred from .parquet extension.
            OutputTarget {
                dest: OutputDest::File(out_parquet.clone()),
                format: None,
                compress_payload: false,
            },
        ],
        filter: Filter::default(),
        bpf_filter: None,
        unidirectional: false,
    };
    let report = export_multi(&input, &opts).unwrap();

    assert_eq!(report.outputs.len(), 2);
    assert_eq!(report.outputs[0].packets_written, 3);
    assert_eq!(report.outputs[1].packets_written, 3);

    // JSON output: three newline-delimited records.
    let json_content = std::fs::read_to_string(&out_json).unwrap();
    assert_eq!(json_content.lines().count(), 3);
    for line in json_content.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("must be valid JSON");
        assert!(v["timestamp_ns"].is_number());
    }

    // Parquet output: magic bytes PAR1 at start and end.
    let pq_bytes = std::fs::read(&out_parquet).unwrap();
    assert!(pq_bytes.len() >= 8);
    assert_eq!(&pq_bytes[..4], b"PAR1");
    assert_eq!(&pq_bytes[pq_bytes.len() - 4..], b"PAR1");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&out_json);
    let _ = std::fs::remove_file(&out_parquet);
}

/// `ExportFormat::parse` accepts all documented format aliases (case-insensitive).
#[test]
fn test_export_format_parse_accepts_all_aliases() {
    assert_eq!(ExportFormat::parse("json"), Some(ExportFormat::Json));
    assert_eq!(ExportFormat::parse("JSON"), Some(ExportFormat::Json));
    assert_eq!(ExportFormat::parse("jsonl"), Some(ExportFormat::Json));
    assert_eq!(ExportFormat::parse("ndjson"), Some(ExportFormat::Json));
    assert_eq!(ExportFormat::parse("parquet"), Some(ExportFormat::Parquet));
    assert_eq!(ExportFormat::parse("PARQUET"), Some(ExportFormat::Parquet));
    assert_eq!(ExportFormat::parse("avro"), Some(ExportFormat::Avro));
    assert_eq!(ExportFormat::parse("AVRO"), Some(ExportFormat::Avro));
    assert_eq!(ExportFormat::parse("csv"), None);
    assert_eq!(ExportFormat::parse(""), None);
}

// ── #9: min-flow-packets integration tests ───────────────────────────────────

/// Export skips flows that have fewer packets than the threshold.
/// Mirrors the `resolve_min_flow_filter` pre-scan logic used by the CLI.
#[test]
fn test_export_min_flow_packets_excludes_small_flows() {
    // Flow A: 3 packets (qualifies at threshold=2)
    // Flow B: 1 packet  (excluded at threshold=2)
    let fa = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, &[0u8; 8]);
    let fb = eth_ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 2000, 443, &[0u8; 8]);
    let pcap_data = build_pcap(&[
        (1, 0, fa.clone()),
        (2, 0, fa.clone()),
        (3, 0, fa.clone()),
        (4, 0, fb.clone()),
    ]);
    let input = write_tmp_pcap("export_minfp_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_minfp_out.jsonl");

    let counts = count_flows_in_file(&input, &Filter::default(), None, true).unwrap();
    let qualifying: FxHashSet<u64> = counts
        .into_iter()
        .filter(|(_, c)| *c >= 2)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(qualifying.len(), 1, "only flow A should qualify");

    let filter = Filter {
        flow_ids: qualifying,
        unidirectional: true,
        ..Default::default()
    };

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        filter,
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 3,
        "only flow A's 3 packets exported"
    );

    let content = std::fs::read_to_string(&output).unwrap();
    assert_eq!(content.lines().count(), 3);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// A flow with exactly N packets meets the threshold and must be included.
#[test]
fn test_min_flow_packets_boundary_exactly_n_qualifies() {
    let fa = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, &[]);
    let fb = eth_ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 2000, 443, &[]);
    // Flow A: exactly 2 packets — threshold is 2 → must qualify.
    // Flow B: 1 packet — must be excluded.
    let pcap_data = build_pcap(&[(1, 0, fa.clone()), (2, 0, fa.clone()), (3, 0, fb.clone())]);
    let input = write_tmp_pcap("minfp_boundary_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("minfp_boundary_out.pcap");

    let counts = count_flows_in_file(&input, &Filter::default(), None, true).unwrap();
    let qualifying: FxHashSet<u64> = counts
        .into_iter()
        .filter(|(_, c)| *c >= 2)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        qualifying.len(),
        1,
        "flow A (count == threshold) must qualify"
    );

    let filter = Filter {
        flow_ids: qualifying,
        unidirectional: true,
        ..Default::default()
    };

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 2,
        "exactly-N flow should be included"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// When all packets belong to a single flow, min-flow-packets keeps them all.
#[test]
fn test_min_flow_packets_single_flow_all_qualify() {
    let frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 443, 0x02, &[]);
    let pcap_data = build_pcap(&[
        (1, 0, frame.clone()),
        (2, 0, frame.clone()),
        (3, 0, frame.clone()),
    ]);
    let input = write_tmp_pcap("minfp_single_flow_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("minfp_single_flow_out.pcap");

    let counts = count_flows_in_file(&input, &Filter::default(), None, false).unwrap();
    assert_eq!(counts.len(), 1);
    let qualifying: FxHashSet<u64> = counts
        .into_iter()
        .filter(|(_, c)| *c >= 3)
        .map(|(id, _)| id)
        .collect();

    let filter = Filter {
        flow_ids: qualifying,
        ..Default::default()
    };

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 3,
        "all packets from single qualifying flow"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// min-flow-packets across a two-file merge via `sort_files`:
/// packets from qualifying flows survive after the merge.
#[test]
fn test_min_flow_packets_with_multi_file_sort() {
    // File A: flow A (3 pkts) + flow B (1 pkt, will be excluded)
    // File B: flow A (2 more pkts, same 5-tuple)
    // Threshold = 4 → flow A qualifies (5 total), flow B does not (1 total)
    let fa = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, &[]);
    let fb = eth_ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 2000, 443, &[]);

    let pcap_a = build_pcap(&[
        (1, 0, fa.clone()),
        (2, 0, fa.clone()),
        (3, 0, fa.clone()),
        (4, 0, fb.clone()),
    ]);
    let pcap_b = build_pcap(&[(5, 0, fa.clone()), (6, 0, fa.clone())]);
    let input_a = write_tmp_pcap("minfp_multi_a.pcap", &pcap_a);
    let input_b = write_tmp_pcap("minfp_multi_b.pcap", &pcap_b);
    let output = std::env::temp_dir().join("minfp_multi_out.pcap");

    // Count across both files.
    let paths: &[&std::path::Path] = &[input_a.as_path(), input_b.as_path()];
    let mut merged: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for path in paths {
        let counts = count_flows_in_file(path, &Filter::default(), None, true).unwrap();
        for (id, c) in counts {
            *merged.entry(id).or_default() += c;
        }
    }
    let qualifying: FxHashSet<u64> = merged
        .into_iter()
        .filter(|(_, c)| *c >= 4)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        qualifying.len(),
        1,
        "only flow A qualifies across both files"
    );

    let filter = Filter {
        flow_ids: qualifying,
        unidirectional: true,
        ..Default::default()
    };

    let opts = SortOptions {
        output: output.clone(),
        filter,
        ..SortOptions::default()
    };
    let report = sort_files(paths, &opts).unwrap();
    assert_eq!(
        report.packets_written, 5,
        "all 5 flow-A packets from both files"
    );

    let _ = std::fs::remove_file(&input_a);
    let _ = std::fs::remove_file(&input_b);
    let _ = std::fs::remove_file(&output);
}

// ── #10: time-slice boundary and empty-window tests ──────────────────────────

/// A packet whose timestamp falls exactly on a slice boundary (T == slice_start +
/// slice_secs) opens a new output file — it must not go to the previous slice.
#[test]
fn test_sort_time_slice_packet_exactly_on_boundary_starts_new_file() {
    let payload = vec![0xABu8; 20];
    // Slice interval: 3600s (1 h).
    // Packet 1 at T=0   → slice starting at 0s
    // Packet 2 at T=3600 exactly → must trigger rotation → new slice starting at 3600s
    let pcap_data = build_pcap(&[(0, 0, payload.clone()), (3600, 0, payload.clone())]);

    let input = write_tmp_pcap("slice_boundary_in.pcap", &pcap_data);
    let out_dir = std::env::temp_dir().join("pcap_slice_boundary_out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let opts = SortOptions {
        output: out_dir.clone(),
        slice_secs: Some(3600),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 2);
    assert_eq!(
        report.files_written.len(),
        2,
        "boundary packet must open a new file"
    );

    // First file has 1 packet (T=0), second file has 1 packet (T=3600).
    let mut sizes: Vec<u64> = report
        .files_written
        .iter()
        .map(|f| {
            let b = std::fs::read(f).unwrap();
            let _ = std::fs::remove_file(f);
            // Subtract 24-byte global header; each packet record is 16 + payload_len.
            let pkt_bytes = b.len() as u64 - 24;
            pkt_bytes / (16 + 20) // records
        })
        .collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![1, 1], "one packet per slice");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir(&out_dir);
}

/// When packets skip an entire slice interval, no output file is produced for
/// the empty window — the writer must not create zero-byte files.
#[test]
fn test_sort_time_slice_empty_window_produces_no_file() {
    let payload = vec![0xCDu8; 20];
    // Slice interval: 3600s.
    // Packet 1 at T=0     → slice 0 (0..3600s)
    // Packet 2 at T=7201  → slice 2 (7200..10800s)   — slice 1 is empty
    let pcap_data = build_pcap(&[(0, 0, payload.clone()), (7201, 0, payload.clone())]);

    let input = write_tmp_pcap("slice_empty_window_in.pcap", &pcap_data);
    let out_dir = std::env::temp_dir().join("pcap_slice_empty_window_out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let opts = SortOptions {
        output: out_dir.clone(),
        slice_secs: Some(3600),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 2);
    assert_eq!(
        report.files_written.len(),
        2,
        "only two files: no file for the empty intermediate slice"
    );

    for f in &report.files_written {
        let bytes = std::fs::read(f).unwrap();
        assert!(
            bytes.len() > 24,
            "each output file must contain at least one packet record"
        );
        let _ = std::fs::remove_file(f);
    }

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir(&out_dir);
}

/// Three consecutive packets that all fall within the same slice produce a
/// single output file.
#[test]
fn test_sort_time_slice_all_same_window_single_file() {
    let payload = vec![0xEFu8; 20];
    let pcap_data = build_pcap(&[
        (100, 0, payload.clone()),
        (200, 0, payload.clone()),
        (3599, 0, payload.clone()), // still within the first 3600s window
    ]);

    let input = write_tmp_pcap("slice_same_window_in.pcap", &pcap_data);
    let out_dir = std::env::temp_dir().join("pcap_slice_same_window_out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let opts = SortOptions {
        output: out_dir.clone(),
        slice_secs: Some(3600),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();

    assert_eq!(report.packets_written, 3);
    assert_eq!(
        report.files_written.len(),
        1,
        "all three packets in one slice"
    );

    for f in &report.files_written {
        let _ = std::fs::remove_file(f);
    }
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir(&out_dir);
}

// ── #11: compound BPF expression integration tests ───────────────────────────

/// `not udp` passes TCP and ICMP but drops UDP packets.
#[test]
fn test_bpf_not_udp_excludes_udp_keeps_others() {
    let tcp = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x02, &[]);
    let udp = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5001, 53, &[]);
    let pcap_data = build_pcap(&[(1, 0, tcp), (2, 0, udp)]);
    let input = write_tmp_pcap("bpf_not_udp_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_not_udp_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("not udp").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 1, "only TCP should pass 'not udp'");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// `tcp or udp` passes both TCP and UDP but not non-IP frames.
#[test]
fn test_bpf_tcp_or_udp_passes_both_protocols() {
    let tcp = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 443, 0x02, &[]);
    let udp = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5001, 53, &[]);
    // Raw ARP-like frame (no IP layer).
    let arp = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08,
        0x06, // EtherType = ARP
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x0a,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];
    let pcap_data = build_pcap(&[(1, 0, tcp), (2, 0, udp), (3, 0, arp)]);
    let input = write_tmp_pcap("bpf_tcp_or_udp_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_tcp_or_udp_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("tcp or udp").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 2, "TCP and UDP pass; ARP must not");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// Nested parentheses: `(tcp and port 80) or (udp and port 53)`.
/// Packets matching either sub-expression pass; all others are dropped.
#[test]
fn test_bpf_nested_parentheses_or_of_and() {
    let tcp80 = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 5000, 80, 0x02, &[]);
    let udp53 = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 5001, 53, &[]);
    let tcp443 = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 5002, 443, 0x02, &[]); // no match
    let udp80 = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 5003, 80, &[]); // port matches but wrong proto half

    let pcap_data = build_pcap(&[(1, 0, tcp80), (2, 0, udp53), (3, 0, tcp443), (4, 0, udp80)]);
    let input = write_tmp_pcap("bpf_nested_or_and_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_nested_or_and_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("(tcp and port 80) or (udp and port 53)").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 2,
        "only TCP/80 and UDP/53 should pass"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// Precedence: `tcp and port 80 or udp` parses as `(tcp and port 80) or udp`.
/// UDP packets must pass even though their port is not 80.
#[test]
fn test_bpf_precedence_and_binds_tighter_than_or() {
    let tcp80 = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 5000, 80, 0x02, &[]);
    let tcp443 = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 5001, 443, 0x02, &[]); // must NOT pass
    let udp53 = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 5002, 53, &[]); // must pass (UDP)
    let udp443 = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 5003, 443, &[]); // must pass (UDP)

    let pcap_data = build_pcap(&[(1, 0, tcp80), (2, 0, tcp443), (3, 0, udp53), (4, 0, udp443)]);
    let input = write_tmp_pcap("bpf_precedence_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_precedence_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("tcp and port 80 or udp").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 3,
        "TCP/80 + both UDP packets; TCP/443 must be excluded"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// `not (tcp or udp)` keeps non-IP frames and drops all TCP/UDP.
#[test]
fn test_bpf_not_of_or_group_keeps_non_ip() {
    let tcp = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0x02, &[]);
    let udp = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5001, 53, &[]);
    let arp = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];
    let pcap_data = build_pcap(&[(1, 0, tcp), (2, 0, udp), (3, 0, arp)]);
    let input = write_tmp_pcap("bpf_not_or_group_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_not_or_group_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("not (tcp or udp)").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 1,
        "only non-IP ARP frame should pass"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

/// `tcp and src net 10.0.0.0/8 and not dst port 80` — three-clause compound.
#[test]
fn test_bpf_three_clause_compound() {
    // Passes: TCP, from 10.x, not dst 80
    let pass = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5000, 443, 0x02, &[]);
    // Fails: TCP, from 10.x, but dst 80
    let fail_port = eth_ipv4_tcp([10, 0, 0, 1], [8, 8, 8, 8], 5001, 80, 0x02, &[]);
    // Fails: TCP, not from 10.x
    let fail_net = eth_ipv4_tcp([192, 168, 1, 1], [8, 8, 8, 8], 5002, 443, 0x02, &[]);
    // Fails: UDP from 10.x (wrong proto)
    let fail_proto = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 5003, 443, &[]);

    let pcap_data = build_pcap(&[
        (1, 0, pass),
        (2, 0, fail_port),
        (3, 0, fail_net),
        (4, 0, fail_proto),
    ]);
    let input = write_tmp_pcap("bpf_three_clause_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("bpf_three_clause_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("tcp and src net 10.0.0.0/8 and not dst port 80").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 1,
        "only the first packet passes all clauses"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

// ── Fixture-based tests (real-world-like PCAPs generated by gen_fixtures) ─────
//
// Files are committed under tests/fixtures/ and generated by:
//   cargo run --bin gen_fixtures -- tests/fixtures

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

// ── http_session.pcap: 9-packet TCP HTTP session ─────────────────────────────

#[test]
fn test_fixture_http_session_sort_roundtrip() {
    let input = fixture("http_session.pcap");
    let output = std::env::temp_dir().join("fx_http_sort_out.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 9);
    assert_eq!(report.files_written.len(), 1);

    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(&bytes[0..4], &0xa1b2_c3d4u32.to_le_bytes());

    // Timestamps must be non-decreasing.
    let mut prev_ts: u64 = 0;
    let mut off = 24usize;
    while off + 16 <= bytes.len() {
        let ts_sec = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as u64;
        let ts_usec = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as u64;
        let ts = ts_sec * 1_000_000 + ts_usec;
        assert!(ts >= prev_ts, "output timestamps must be non-decreasing");
        prev_ts = ts;
        let caplen = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
        off += 16 + caplen;
    }

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_http_session_export_json_all_tcp() {
    let input = fixture("http_session.pcap");
    let output = std::env::temp_dir().join("fx_http_export.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 9);

    let content = std::fs::read_to_string(&output).unwrap();
    assert_eq!(content.lines().count(), 9);
    for line in content.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["protocol"], 6, "all packets in http_session must be TCP");
        assert!(
            v["tcp_flags"].is_number(),
            "TCP packets must have tcp_flags"
        );
    }

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_http_session_bpf_dst_port_80() {
    // Packets going *to* port 80 are the client→server direction:
    // SYN, ACK, GET, client-ACK-after-response, final-ACK = 5 packets.
    let input = fixture("http_session.pcap");
    let output = std::env::temp_dir().join("fx_http_bpf_dport80.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("tcp and dst port 80").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 5,
        "5 client→server packets target port 80"
    );

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_http_session_single_bidirectional_flow() {
    let input = fixture("http_session.pcap");
    let counts = count_flows_in_file(&input, &Filter::default(), None, false).unwrap();
    assert_eq!(
        counts.len(),
        1,
        "http_session has exactly one bidirectional flow"
    );
    let total: u64 = counts.values().sum();
    assert_eq!(total, 9);
}

// ── dns_exchange.pcap: 6 UDP DNS packets (3 query/response pairs) ─────────────

#[test]
fn test_fixture_dns_all_packets_match_port_53() {
    let input = fixture("dns_exchange.pcap");
    let output = std::env::temp_dir().join("fx_dns_all.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("udp and port 53").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 6,
        "all 6 DNS packets match 'udp and port 53'"
    );

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_dns_queries_only() {
    // Queries go *to* port 53; responses come *from* port 53.
    let input = fixture("dns_exchange.pcap");
    let output = std::env::temp_dir().join("fx_dns_queries.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("dst port 53").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 3,
        "only the 3 query packets go to port 53"
    );

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_dns_export_json_all_udp() {
    let input = fixture("dns_exchange.pcap");
    let output = std::env::temp_dir().join("fx_dns_export.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 6);

    let content = std::fs::read_to_string(&output).unwrap();
    for line in content.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["protocol"], 17, "all DNS packets must be UDP");
        assert!(
            v["flow_id"].is_u64() || v["flow_id"].is_i64(),
            "UDP DNS packets have a numeric flow_id"
        );
    }

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_dns_three_bidirectional_flows() {
    let input = fixture("dns_exchange.pcap");
    let counts = count_flows_in_file(&input, &Filter::default(), None, false).unwrap();
    assert_eq!(
        counts.len(),
        3,
        "three DNS query/response pairs = 3 bidirectional flows"
    );
}

// ── arp_scan.pcap: 12 ARP packets, no IP layer ────────────────────────────────

#[test]
fn test_fixture_arp_sort_survives_non_ip() {
    // Sort must succeed even though all packets are non-IP (flow_key = None).
    let input = fixture("arp_scan.pcap");
    let output = std::env::temp_dir().join("fx_arp_sort.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 12);

    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(&bytes[0..4], &0xa1b2_c3d4u32.to_le_bytes());

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_arp_export_json_null_ip_fields() {
    let input = fixture("arp_scan.pcap");
    let output = std::env::temp_dir().join("fx_arp_export.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 12);

    let content = std::fs::read_to_string(&output).unwrap();
    assert_eq!(content.lines().count(), 12);
    for line in content.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v["src_ip"].is_null(), "ARP packets have no IP src");
        assert!(v["dst_ip"].is_null(), "ARP packets have no IP dst");
        assert!(v["flow_id"].is_null(), "ARP packets have no flow_id");
    }

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_arp_bpf_tcp_matches_none() {
    let input = fixture("arp_scan.pcap");
    let output = std::env::temp_dir().join("fx_arp_bpf_tcp.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("tcp").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 0, "no TCP packets in arp_scan");
    assert!(report.files_written.is_empty());

    let _ = std::fs::remove_file(&output);
}

// ── mixed.pcap: 14 packets — TCP (10), UDP/DNS (1), ARP (3) ─────────────────

#[test]
fn test_fixture_mixed_total_packet_count() {
    let input = fixture("mixed.pcap");
    let output = std::env::temp_dir().join("fx_mixed_sort.pcap");

    let opts = SortOptions {
        output: output.clone(),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 14);

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_mixed_bpf_tcp_count() {
    let input = fixture("mixed.pcap");
    let output = std::env::temp_dir().join("fx_mixed_bpf_tcp.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("tcp").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 10, "mixed.pcap has 10 TCP packets");

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_mixed_bpf_not_tcp_or_udp_keeps_arp() {
    let input = fixture("mixed.pcap");
    let output = std::env::temp_dir().join("fx_mixed_bpf_arp.pcap");

    let opts = SortOptions {
        output: output.clone(),
        bpf_filter: Some(bpf::parse("not (tcp or udp)").unwrap()),
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 3,
        "mixed.pcap has 3 non-IP (ARP) packets"
    );

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_mixed_two_tcp_flows() {
    // mixed.pcap has two distinct TCP flows (one to port 443, one to port 80).
    let input = fixture("mixed.pcap");
    let filter = Filter {
        protocols: vec![6], // TCP only
        ..Default::default()
    };
    let counts = count_flows_in_file(&input, &filter, None, false).unwrap();
    assert_eq!(counts.len(), 2, "mixed.pcap has exactly two TCP flows");
}

#[test]
fn test_fixture_mixed_export_parquet_succeeds() {
    let input = fixture("mixed.pcap");
    let output = std::env::temp_dir().join("fx_mixed_export.parquet");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Parquet),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 14);

    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(&bytes[..4], b"PAR1");
    assert_eq!(&bytes[bytes.len() - 4..], b"PAR1");

    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_fixture_mixed_min_flow_packets_threshold() {
    // TCP flow 1 (→ port 443): 6 packets. TCP flow 2 (→ port 80): 4 packets.
    // With threshold=5, only flow 1 qualifies.
    let input = fixture("mixed.pcap");

    let tcp_filter = Filter {
        protocols: vec![6],
        ..Default::default()
    };
    let counts = count_flows_in_file(&input, &tcp_filter, None, false).unwrap();
    let qualifying: FxHashSet<u64> = counts
        .into_iter()
        .filter(|(_, c)| *c >= 5)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        qualifying.len(),
        1,
        "only the 6-packet flow qualifies at threshold=5"
    );

    let output = std::env::temp_dir().join("fx_mixed_minfp.pcap");
    let effective = Filter {
        flow_ids: qualifying,
        ..tcp_filter
    };

    let opts = SortOptions {
        output: output.clone(),
        filter: effective,
        ..SortOptions::default()
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(
        report.packets_written, 6,
        "only the 6-packet TCP flow survives"
    );

    let _ = std::fs::remove_file(&output);
}

// ── Round-trip / decoder tests ────────────────────────────────────────────────

#[test]
fn test_export_parquet_roundtrip_readable() {
    use parquet::file::reader::{FileReader, SerializedFileReader};

    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0xAB; 8]);
    let pcap_data = build_pcap(&[(1, 0, frame.clone()), (2, 0, frame)]);
    let input = write_tmp_pcap("export_parquet_rt_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_parquet_rt_out.parquet");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Parquet),
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 2);

    // Reopen and read every row back.
    let file = std::fs::File::open(&output).unwrap();
    let reader = SerializedFileReader::new(file).expect("parquet file must parse");
    let meta = reader.metadata();
    assert_eq!(meta.file_metadata().num_rows(), 2, "two rows expected");
    let row_iter = reader.get_row_iter(None).unwrap();
    let mut seen = 0;
    for row in row_iter {
        let row = row.unwrap();
        let dump = format!("{row:?}");
        // Field presence is enough — confirms columns are wired up correctly.
        assert!(dump.contains("src_ip"));
        assert!(dump.contains("flow_id"));
        assert!(dump.contains("payload"));
        seen += 1;
    }
    assert_eq!(seen, 2);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_avro_roundtrip_readable() {
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0xCD; 4]);
    let pcap_data = build_pcap(&[(1, 0, frame.clone()), (2, 0, frame)]);
    let input = write_tmp_pcap("export_avro_rt_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_avro_rt_out.avro");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Avro),
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    // Reopen and decode every record back via apache_avro.
    let file = std::fs::File::open(&output).unwrap();
    let reader = apache_avro::Reader::new(file).expect("avro file must parse");
    let records: Vec<_> = reader
        .collect::<Result<_, _>>()
        .expect("all records decode");
    assert_eq!(records.len(), 2);

    // Spot-check one record: it must contain the expected fields.
    if let apache_avro::types::Value::Record(fields) = &records[0] {
        let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"timestamp_ns"));
        assert!(names.contains(&"flow_id"));
        assert!(names.contains(&"payload"));
    } else {
        panic!("expected a Record value");
    }

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(output.with_extension("avsc"));
}

#[test]
fn test_export_compress_payload_json_roundtrip() {
    // Verify compress_payload=true on JSON produces a file whose base64+zstd
    // payload round-trips back to the original bytes.
    use base64::Engine as _;

    let payload = vec![0x42u8; 512]; // compressible (repeated bytes)
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &payload);
    let pcap_data = build_pcap(&[(1, 0, frame)]);
    let input = write_tmp_pcap("export_json_zstd_rt_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_zstd_rt_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        compress_payload: true,
        ..ExportOptions::default()
    };
    let report = export_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 1);

    let line = std::fs::read_to_string(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(v["payload_encoding"], "zstd+base64");
    let encoded = v["payload"].as_str().unwrap();
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let decoded = zstd::decode_all(compressed.as_slice()).unwrap();
    // The decoded blob is the full captured Ethernet frame. It must contain
    // the original UDP payload bytes verbatim.
    assert!(
        decoded.windows(payload.len()).any(|w| w == payload),
        "decoded ({}B) must contain the {}-byte payload",
        decoded.len(),
        payload.len()
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_compress_payload_avro_roundtrip() {
    // Avro uses Codec::Zstandard when compress_payload=true. The file must
    // still be decodable by apache_avro::Reader.
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0xEE; 64]);
    let pcap_data = build_pcap(&[(1, 0, frame.clone()), (2, 0, frame)]);
    let input = write_tmp_pcap("export_avro_zstd_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_avro_zstd_out.avro");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Avro),
        compress_payload: true,
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    let file = std::fs::File::open(&output).unwrap();
    let reader = apache_avro::Reader::new(file).unwrap();
    let count = reader.into_iter().count();
    assert_eq!(count, 2, "zstd-compressed avro must decode to 2 records");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(output.with_extension("avsc"));
}

#[test]
fn test_export_compress_payload_parquet_roundtrip() {
    // Parquet uses Compression::ZSTD when compress_payload=true. Reopen with
    // SerializedFileReader and confirm the rows are still readable.
    use parquet::file::reader::{FileReader, SerializedFileReader};

    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0xFA; 32]);
    let pcap_data = build_pcap(&[(1, 0, frame.clone()), (2, 0, frame)]);
    let input = write_tmp_pcap("export_parquet_zstd_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_parquet_zstd_out.parquet");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Parquet),
        compress_payload: true,
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    let file = std::fs::File::open(&output).unwrap();
    let reader = SerializedFileReader::new(file).unwrap();
    assert_eq!(reader.metadata().file_metadata().num_rows(), 2);
    let count = reader.get_row_iter(None).unwrap().count();
    assert_eq!(count, 2);

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn test_export_json_flow_id_is_numeric_u64() {
    // Regression: previously emitted as a 16-hex string, breaking cross-sink
    // joins with Avro/Parquet which emit the same value as i64.
    let frame = eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53, &[0; 4]);
    let pcap_data = build_pcap(&[(1, 0, frame)]);
    let input = write_tmp_pcap("export_json_flowid_in.pcap", &pcap_data);
    let output = std::env::temp_dir().join("export_json_flowid_out.jsonl");

    let opts = ExportOptions {
        output: output.clone(),
        format: Some(ExportFormat::Json),
        ..ExportOptions::default()
    };
    export_file(&input, &opts).unwrap();

    let line = std::fs::read_to_string(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    // Must be a JSON number (u64-safe), not a string.
    let fid = v["flow_id"].as_u64().expect("flow_id must be a u64 number");
    assert_ne!(fid, 0, "flow_id should not be zero for UDP traffic");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}
