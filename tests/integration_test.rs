//! Integration tests for the sort pipeline using hand-crafted PCAP byte buffers.

use std::io::Write;
use std::path::PathBuf;

use pcap_toolkit::filter::{Filter, IpNet, PortRange};
use pcap_toolkit::flow::FlowKey;
use pcap_toolkit::sort::{SortOptions, parse_slice, sort_file};

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
        slice_secs: None,
        on_disk: false,
        filter: Filter::default(),
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
        slice_secs: None,
        on_disk: false,
        filter: Filter::default(),
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
        slice_secs: None,
        on_disk: true,
        filter: Filter::default(),
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
        on_disk: false,
        filter: Filter::default(),
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
        slice_secs: None,
        on_disk: false,
        filter: Filter::default(),
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
    let total_len = (20 + udp_len) as u16;
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
fn test_parse_slice_values() {
    assert_eq!(parse_slice("1h").unwrap(), 3600);
    assert_eq!(parse_slice("30m").unwrap(), 1800);
    assert_eq!(parse_slice("2d").unwrap(), 172800);
    assert_eq!(parse_slice("60s").unwrap(), 60);
    assert_eq!(parse_slice("300").unwrap(), 300);
    assert!(parse_slice("bad").is_err());
}
