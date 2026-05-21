//! Integration tests for the sort pipeline using hand-crafted PCAP byte buffers.

use std::io::Write;
use std::path::PathBuf;

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
    };
    let report = sort_file(&input, &opts).unwrap();
    assert_eq!(report.packets_written, 0);
    assert_eq!(report.files_written.len(), 0);

    let _ = std::fs::remove_file(&input);
    // No output file created for empty input.
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
