//! Generates deterministic PCAP fixture files for integration tests.
//! Run: cargo run --bin gen_fixtures -- tests/fixtures

#![allow(clippy::too_many_arguments, clippy::vec_init_then_push)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

fn pcap_header(snaplen: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&4u16.to_le_bytes());
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&snaplen.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    b
}

fn pcap_record(ts_sec: u32, ts_usec: u32, data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut b = Vec::new();
    b.extend_from_slice(&ts_sec.to_le_bytes());
    b.extend_from_slice(&ts_usec.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(data);
    b
}

fn eth_hdr(src: [u8; 6], dst: [u8; 6], etype: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&dst);
    b.extend_from_slice(&src);
    b.extend_from_slice(&etype.to_be_bytes());
    b
}

fn ipv4_hdr(proto: u8, src: [u8; 4], dst: [u8; 4], total_len: u16, id: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(0x45);
    b.push(0x00);
    b.extend_from_slice(&total_len.to_be_bytes());
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0x40, 0x00]); // DF
    b.push(64);
    b.push(proto);
    b.extend_from_slice(&[0x00, 0x00]); // checksum (zeroed)
    b.extend_from_slice(&src);
    b.extend_from_slice(&dst);
    b
}

fn tcp_pkt(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    id: u16,
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let ip_total = (20 + tcp_len) as u16;
    let mut pkt = eth_hdr(src_mac, dst_mac, 0x0800);
    pkt.extend_from_slice(&ipv4_hdr(6, src_ip, dst_ip, ip_total, id));
    // TCP header
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ack.to_be_bytes());
    pkt.push(0x50); // data offset = 5
    pkt.push(flags);
    pkt.extend_from_slice(&[0xff, 0xff]); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent
    pkt.extend_from_slice(payload);
    pkt
}

fn udp_pkt(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    id: u16,
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let ip_total = 20 + udp_len;
    let mut pkt = eth_hdr(src_mac, dst_mac, 0x0800);
    pkt.extend_from_slice(&ipv4_hdr(17, src_ip, dst_ip, ip_total, id));
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(payload);
    pkt
}

fn arp_pkt(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
    op: u16, // 1 = request, 2 = reply
) -> Vec<u8> {
    let dst_mac = if op == 1 {
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    } else {
        target_mac
    };
    let mut pkt = eth_hdr(sender_mac, dst_mac, 0x0806);
    pkt.extend_from_slice(&[0x00, 0x01]); // hw type = Ethernet
    pkt.extend_from_slice(&[0x08, 0x00]); // proto = IP
    pkt.push(6); // hw size
    pkt.push(4); // proto size
    pkt.extend_from_slice(&op.to_be_bytes());
    pkt.extend_from_slice(&sender_mac);
    pkt.extend_from_slice(&sender_ip);
    pkt.extend_from_slice(&target_mac);
    pkt.extend_from_slice(&target_ip);
    pkt
}

fn write_pcap(path: &Path, packets: &[(u32, u32, Vec<u8>)]) {
    let mut data = pcap_header(65535);
    for (sec, usec, pkt) in packets {
        data.extend_from_slice(&pcap_record(*sec, *usec, pkt));
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&data).unwrap();
    println!(
        "wrote {} ({} packets, {} bytes)",
        path.display(),
        packets.len(),
        data.len()
    );
}

fn gen_http_session(out: &Path) {
    // Realistic HTTP/1.1 GET session.
    // Client: 192.168.1.10:54321  Server: 93.184.216.34:80
    // Base ts: 2024-01-15 10:00:00 UTC = 1705312800
    let client_ip = [192, 168, 1, 10];
    let server_ip = [93, 184, 216, 34];
    let client_mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    let server_mac = [0x00, 0x50, 0x56, 0x01, 0x02, 0x03];
    let client_port: u16 = 54321;
    let server_port: u16 = 80;

    let get_req =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pcap-test/1.0\r\nAccept: */*\r\n\r\n";
    let http_resp_hdr = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 26\r\nConnection: close\r\n\r\n";
    let http_resp_body = b"<html>Hello World!</html>\n";

    let base: u32 = 1_705_312_800;
    let mut pkts: Vec<(u32, u32, Vec<u8>)> = Vec::new();

    // SYN
    pkts.push((
        base,
        0,
        tcp_pkt(
            client_mac,
            server_mac,
            client_ip,
            server_ip,
            client_port,
            server_port,
            1000,
            0,
            0x02,
            &[],
            1,
        ),
    ));
    // SYN-ACK
    pkts.push((
        base,
        100_000,
        tcp_pkt(
            server_mac,
            client_mac,
            server_ip,
            client_ip,
            server_port,
            client_port,
            5000,
            1001,
            0x12,
            &[],
            2,
        ),
    ));
    // ACK
    pkts.push((
        base,
        200_000,
        tcp_pkt(
            client_mac,
            server_mac,
            client_ip,
            server_ip,
            client_port,
            server_port,
            1001,
            5001,
            0x10,
            &[],
            3,
        ),
    ));
    // GET request
    pkts.push((
        base,
        250_000,
        tcp_pkt(
            client_mac,
            server_mac,
            client_ip,
            server_ip,
            client_port,
            server_port,
            1001,
            5001,
            0x18,
            get_req,
            4,
        ),
    ));
    // Server ACK
    pkts.push((
        base,
        400_000,
        tcp_pkt(
            server_mac,
            client_mac,
            server_ip,
            client_ip,
            server_port,
            client_port,
            5001,
            1001 + get_req.len() as u32,
            0x10,
            &[],
            5,
        ),
    ));
    // HTTP response header + body combined
    let mut resp = Vec::new();
    resp.extend_from_slice(http_resp_hdr);
    resp.extend_from_slice(http_resp_body);
    pkts.push((
        base,
        500_000,
        tcp_pkt(
            server_mac,
            client_mac,
            server_ip,
            client_ip,
            server_port,
            client_port,
            5001,
            1001 + get_req.len() as u32,
            0x18,
            &resp,
            6,
        ),
    ));
    // Client ACK
    pkts.push((
        base,
        600_000,
        tcp_pkt(
            client_mac,
            server_mac,
            client_ip,
            server_ip,
            client_port,
            server_port,
            1001 + get_req.len() as u32,
            5001 + resp.len() as u32,
            0x10,
            &[],
            7,
        ),
    ));
    // FIN-ACK from server
    pkts.push((
        base,
        700_000,
        tcp_pkt(
            server_mac,
            client_mac,
            server_ip,
            client_ip,
            server_port,
            client_port,
            5001 + resp.len() as u32,
            1001 + get_req.len() as u32,
            0x11,
            &[],
            8,
        ),
    ));
    // Final ACK from client
    pkts.push((
        base,
        750_000,
        tcp_pkt(
            client_mac,
            server_mac,
            client_ip,
            server_ip,
            client_port,
            server_port,
            1001 + get_req.len() as u32,
            5001 + resp.len() as u32 + 1,
            0x10,
            &[],
            9,
        ),
    ));

    write_pcap(out, &pkts);
}

fn gen_dns_exchange(out: &Path) {
    // 3 DNS query/response pairs for different domains.
    // Client: 192.168.1.100:ephemeral  DNS server: 8.8.8.8:53
    let client_ip = [192, 168, 1, 100];
    let dns_ip = [8, 8, 8, 8];
    let client_mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    let dns_mac = [0x00, 0x50, 0x56, 0x01, 0x02, 0x04];

    // Minimal DNS query: header + question for "example.com" type A
    // TxID=0x1234, flags=0x0100 (standard query), QDCount=1
    let dns_q1: &[u8] = &[
        0x12, 0x34, // TxID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // QDCount = 1
        0x00, 0x00, // ANCount = 0
        0x00, 0x00, // NSCount = 0
        0x00, 0x00, // ARCount = 0
        // Question: example.com A IN
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // end of name
        0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN
    ];
    // DNS response: TxID=0x1234, answer 93.184.216.34
    let dns_r1: &[u8] = &[
        0x12, 0x34, // TxID
        0x81, 0x80, // Flags: standard response, no error
        0x00, 0x01, // QDCount = 1
        0x00, 0x01, // ANCount = 1
        0x00, 0x00, // NSCount = 0
        0x00, 0x00, // ARCount = 0
        // Question (repeated)
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        // Answer: pointer to name, A, IN, TTL=3600, RDATA=93.184.216.34
        0xc0, 0x0c, // name pointer
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x0e, 0x10, // TTL = 3600
        0x00, 0x04, // RDLENGTH = 4
        0x5d, 0xb8, 0xd8, 0x22, // 93.184.216.34
    ];

    // Second pair: google.com TxID=0x5678
    let dns_q2: &[u8] = &[
        0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 6, b'g', b'o',
        b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
    ];
    let dns_r2: &[u8] = &[
        0x56, 0x78, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 6, b'g', b'o',
        b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x8e, 0xfa, 0x4a,
        0x8a, // 142.250.74.138
    ];

    // Third pair: AAAA query for cloudflare.com TxID=0x9abc
    let dns_q3: &[u8] = &[
        0x9a, 0xbc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, b'c', b'l',
        b'o', b'u', b'd', b'f', b'l', b'a', b'r', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x1c, 0x00,
        0x01, // QTYPE AAAA
    ];
    let dns_r3: &[u8] = &[
        0x9a, 0xbc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 10, b'c', b'l',
        b'o', b'u', b'd', b'f', b'l', b'a', b'r', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x1c, 0x00,
        0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10,
        // 2606:4700:4700::1111
        0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
        0x11,
    ];

    let base: u32 = 1_705_312_810;
    let pkts = vec![
        (
            base,
            0,
            udp_pkt(
                client_mac, dns_mac, client_ip, dns_ip, 51234, 53, dns_q1, 10,
            ),
        ),
        (
            base,
            20_000,
            udp_pkt(
                dns_mac, client_mac, dns_ip, client_ip, 53, 51234, dns_r1, 11,
            ),
        ),
        (
            base,
            100_000,
            udp_pkt(
                client_mac, dns_mac, client_ip, dns_ip, 51235, 53, dns_q2, 12,
            ),
        ),
        (
            base,
            120_000,
            udp_pkt(
                dns_mac, client_mac, dns_ip, client_ip, 53, 51235, dns_r2, 13,
            ),
        ),
        (
            base,
            200_000,
            udp_pkt(
                client_mac, dns_mac, client_ip, dns_ip, 51236, 53, dns_q3, 14,
            ),
        ),
        (
            base,
            220_000,
            udp_pkt(
                dns_mac, client_mac, dns_ip, client_ip, 53, 51236, dns_r3, 15,
            ),
        ),
    ];
    write_pcap(out, &pkts);
}

fn gen_arp_scan(out: &Path) {
    // ARP scan: one host discovering its neighbours.
    // Scanner: 10.0.0.1, scanning 10.0.0.2 through 10.0.0.6
    let scanner_mac = [0x00, 0xde, 0xad, 0xbe, 0xef, 0x01];
    let host_macs: [[u8; 6]; 5] = [
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x02],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x03],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x04],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x05],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x06],
    ];
    let scanner_ip = [10, 0, 0, 1];
    let target_ips: [[u8; 4]; 5] = [
        [10, 0, 0, 2],
        [10, 0, 0, 3],
        [10, 0, 0, 4],
        [10, 0, 0, 5],
        [10, 0, 0, 6],
    ];

    let base: u32 = 1_705_312_820;
    let mut pkts: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    for (i, (target_ip, host_mac)) in target_ips.iter().zip(host_macs.iter()).enumerate() {
        let t_req = base + i as u32 / 10;
        let usec_req = (i as u32 % 10) * 100_000;
        let usec_rep = usec_req + 50_000;
        pkts.push((
            t_req,
            usec_req,
            arp_pkt(scanner_mac, scanner_ip, [0, 0, 0, 0, 0, 0], *target_ip, 1),
        ));
        pkts.push((
            t_req,
            usec_rep,
            arp_pkt(*host_mac, *target_ip, scanner_mac, scanner_ip, 2),
        ));
    }
    // A couple of unreplied requests (hosts 10.0.0.7, 10.0.0.8)
    pkts.push((
        base,
        600_000,
        arp_pkt(
            scanner_mac,
            scanner_ip,
            [0, 0, 0, 0, 0, 0],
            [10, 0, 0, 7],
            1,
        ),
    ));
    pkts.push((
        base,
        700_000,
        arp_pkt(
            scanner_mac,
            scanner_ip,
            [0, 0, 0, 0, 0, 0],
            [10, 0, 0, 8],
            1,
        ),
    ));

    pkts.sort_by_key(|(s, u, _)| (*s as u64) * 1_000_000 + *u as u64);
    write_pcap(out, &pkts);
}

fn gen_mixed(out: &Path) {
    // Mixed traffic: TCP, UDP/DNS, ARP interleaved across 5 seconds.
    // Two TCP flows + DNS + ARP; tests that filters and flow counts work on realistic mixes.
    let mac_a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let mac_b = [0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
    let mac_gw = [0x00, 0xff, 0xff, 0xff, 0xff, 0x01];
    let ip_a = [10, 0, 1, 10];
    let ip_b = [10, 0, 1, 20];
    let ip_gw = [10, 0, 1, 1];
    let ip_ext = [1, 2, 3, 4];

    let base: u32 = 1_705_312_830;
    let mut pkts: Vec<(u32, u32, Vec<u8>)> = Vec::new();

    // ARP: A asks for gateway
    pkts.push((base, 0, arp_pkt(mac_a, ip_a, [0, 0, 0, 0, 0, 0], ip_gw, 1)));
    pkts.push((base, 5_000, arp_pkt(mac_gw, ip_gw, mac_a, ip_a, 2)));

    // TCP flow 1: A→external on port 443 (3 packets each way)
    pkts.push((
        base,
        50_000,
        tcp_pkt(
            mac_a,
            mac_gw,
            ip_a,
            ip_ext,
            12345,
            443,
            100,
            0,
            0x02,
            &[],
            20,
        ),
    ));
    pkts.push((
        base,
        60_000,
        tcp_pkt(
            mac_gw,
            mac_a,
            ip_ext,
            ip_a,
            443,
            12345,
            200,
            101,
            0x12,
            &[],
            21,
        ),
    ));
    pkts.push((
        base,
        70_000,
        tcp_pkt(
            mac_a,
            mac_gw,
            ip_a,
            ip_ext,
            12345,
            443,
            101,
            201,
            0x10,
            &[],
            22,
        ),
    ));
    pkts.push((
        base,
        100_000,
        tcp_pkt(
            mac_a,
            mac_gw,
            ip_a,
            ip_ext,
            12345,
            443,
            101,
            201,
            0x18,
            b"GET / HTTP/1.1\r\n\r\n",
            23,
        ),
    ));
    pkts.push((
        base,
        200_000,
        tcp_pkt(
            mac_gw,
            mac_a,
            ip_ext,
            ip_a,
            443,
            12345,
            201,
            119,
            0x18,
            b"HTTP/1.1 200 OK\r\n\r\n",
            24,
        ),
    ));
    pkts.push((
        base,
        300_000,
        tcp_pkt(
            mac_a,
            mac_gw,
            ip_a,
            ip_ext,
            12345,
            443,
            119,
            219,
            0x11,
            &[],
            25,
        ),
    ));

    // DNS query in between
    let dns_q: &[u8] = &[
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 4, b't', b'e',
        b's', b't', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
    ];
    pkts.push((
        base,
        150_000,
        udp_pkt(mac_a, mac_gw, ip_a, [8, 8, 8, 8], 54321, 53, dns_q, 30),
    ));

    // TCP flow 2: B→external on port 80
    pkts.push((
        base + 1,
        0,
        tcp_pkt(
            mac_b,
            mac_gw,
            ip_b,
            ip_ext,
            22222,
            80,
            500,
            0,
            0x02,
            &[],
            40,
        ),
    ));
    pkts.push((
        base + 1,
        10_000,
        tcp_pkt(
            mac_gw,
            mac_b,
            ip_ext,
            ip_b,
            80,
            22222,
            600,
            501,
            0x12,
            &[],
            41,
        ),
    ));
    pkts.push((
        base + 1,
        20_000,
        tcp_pkt(
            mac_b,
            mac_gw,
            ip_b,
            ip_ext,
            22222,
            80,
            501,
            601,
            0x10,
            &[],
            42,
        ),
    ));
    pkts.push((
        base + 1,
        100_000,
        tcp_pkt(
            mac_b,
            mac_gw,
            ip_b,
            ip_ext,
            22222,
            80,
            501,
            601,
            0x18,
            b"GET /index.html HTTP/1.0\r\n\r\n",
            43,
        ),
    ));

    // ARP broadcast at t+2
    pkts.push((
        base + 2,
        0,
        arp_pkt(mac_b, ip_b, [0, 0, 0, 0, 0, 0], ip_gw, 1),
    ));

    pkts.sort_by_key(|(s, u, _)| (*s as u64) * 1_000_000 + *u as u64);
    write_pcap(out, &pkts);
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/fixtures"));

    std::fs::create_dir_all(&dir).unwrap();
    gen_http_session(&dir.join("http_session.pcap"));
    gen_dns_exchange(&dir.join("dns_exchange.pcap"));
    gen_arp_scan(&dir.join("arp_scan.pcap"));
    gen_mixed(&dir.join("mixed.pcap"));
}
