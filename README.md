# pcap-toolkit

[![CI](https://ci.codeberg.org/api/badges/slundi/pcap-toolkit/status.svg)](https://ci.codeberg.org/slundi/pcap-toolkit)
<!-- [![crates.io](https://img.shields.io/crates/v/pcap-toolkit.svg)](https://crates.io/crates/pcap-toolkit) -->
<!-- [![docs.rs](https://docs.rs/pcap-toolkit/badge.svg)](https://docs.rs/pcap-toolkit) -->
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)

A high-performance CLI for inspecting, filtering, sorting, modifying, replaying, and exporting PCAP captures — designed to handle everything from quick triage to TB-scale data pipeline ingestion.

## Table of Contents

- [Why pcap-toolkit?](#why-pcap-toolkit)
- [Features](#features)
- [Usage](#usage)
- [Configuration](#configuration)
- [Installation](#installation)

## Why pcap-toolkit?

`tcpdump` and `tshark` are powerful but stop short of the data engineering workflows that security analysts and threat hunters actually need: deterministic flow IDs for correlation, columnar export for DuckDB or Snowflake, timestamp shifting for lab replay, or sorting a months-long multi-file capture that doesn't fit in RAM.

`pcap-toolkit` fills that gap. Every operation streams packets with a minimal memory footprint and uses `Rayon` for multi-core throughput — so it stays fast whether your input is a 10 MB sample or a 2 TB archive.

## Features

### Inspection — `info` / `stats`

Extract a full capture summary in a single streaming pass, without loading payloads into RAM:

- Start and end timestamps (millisecond precision)
- Total packet count and byte volume
- Unique source and destination IPs
- Per-flow statistics keyed by 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`
- Deterministic **Flow ID** (`xxh3_64` hash) — bidirectional by default so A→B and B→A share one ID; `--unidirectional` for direction-aware keying

### Filtering

Composable filters applied after sorting, before any output or replay:

| Filter | CLI | Notes |
|--------|-----|-------|
| Protocol | `--proto tcp,udp,icmp` | by name or IP protocol number |
| Source IP / CIDR | `--src-ip 10.0.0.0/8` | exact or prefix, IPv4 and IPv6 |
| Destination IP / CIDR | `--dst-ip 192.168.1.5` | |
| Either endpoint IP | `--ip 10.0.0.0/8` | OR across src and dst |
| Source port / range | `--src-port 1024-65535` | TCP and UDP only |
| Destination port / range | `--dst-port 443` | |
| Either endpoint port | `--port 80,443` | |
| Flow ID | `--flow-id <hex>` | one or more, comma-separated |
| Time window | `--from` / `--to` | RFC 3339 or ms epoch |
| TCP flags | `--tcp-flags SYN,RST` | exact or `any` match |
| Packet length | `--min-len` / `--max-len` | applied to captured length |
| BPF expression | `--filter "tcp and dst port 443"` | pure-Rust implementation, no libpcap required |

Rules of the same type are OR-ed; different types are AND-ed. Full boolean control (`and` / `or` / `not`) is available in the TOML configuration.

### Two-Pass Sorting

Strict chronological ordering with a near-zero RAM footprint (~20 bytes per packet):

1. **First pass** — build a `(timestamp_ns, byte_offset, length)` index. Kept in memory for normal files; streamed to a `.idx` sidecar on disk for TB-scale inputs (~20 MB index per 1 M packets).
2. **Second pass** — sort the index, then seek-and-stream packets in order to the output pipeline.

Sorted output can be time-sliced into separate files (hourly, daily, or any custom interval).

### Traffic Modification

Applied during the second pass, before writing or replaying:

- **Payload truncation** — `--max-payload-bytes N`: keep only the first N bytes of the application payload, preserving all Ethernet / IP / transport headers. Shrinks storage while retaining full header fidelity for analysis.
- **MTU truncation** — `--mtu-trunc N`: cap every packet so that Layer 3 and above (the IP packet) is at most N bytes; the Layer 2 (Ethernet / VLAN) header is not counted. Equivalent to tcprewrite's `--mtu-trunc`. Unlike `--max-payload-bytes` this is a hard cap that may cut into the transport payload. IP/UDP length fields and checksums are recomputed.
- **Timestamp shifting** — provide a target start datetime (ms epoch); all timestamps are shifted by the computed delta. Useful for re-anchoring old captures to a lab timeline.
- **IP address mapping** — replace specific IPs with others (`--replace-ip 10.0.0.1=192.168.1.1`) or via a TOML mapping table. Checksums are automatically recomputed after any header change.

### Export

Convert filtered, sorted captures into modern data formats:

- **JSON** — one document per packet with parsed layer fields, flow ID, and Base64/hex payload; optional Zstd payload compression.
- **Apache Parquet** — typed columnar schema (timestamps, IPs as integers, ports, flags, flow ID, payload). Row groups encoded in parallel with `Rayon`.
- **Apache Avro** — schema-first encoding; Avro schema file emitted alongside the data for self-describing datasets.

All formats integrate directly with DuckDB, Spark, Snowflake, and Elasticsearch.

### Live Replay

Send a processed capture back onto a network interface:

- Honour original inter-packet timing or apply a speed multiplier (`--speed 2.0`, `--speed max`)
- Accepts replay interface via CLI or TOML config
- Requires `CAP_NET_RAW`; missing capability is caught early with a clear error

## Usage

```sh
# Summarise a capture
pcap-toolkit info traffic.pcap

# Show per-flow statistics
pcap-toolkit stats traffic.pcap

# Filter to HTTPS traffic from a subnet and export to Parquet
pcap-toolkit export --proto tcp --dst-port 443 --src-ip 10.0.0.0/8 \
  --format parquet --output out.parquet traffic.pcap

# Sort a large capture and split into hourly files
pcap-toolkit sort --slice 1h --output sorted/ traffic.pcap

# Shift timestamps so the capture starts now, then replay at 2× speed
pcap-toolkit replay --shift now --speed 2.0 --interface eth0 traffic.pcap

# Extract a specific flow by ID
pcap-toolkit export --flow-id a3f2c1b0e4d5... --format json traffic.pcap

# Use a BPF expression for complex filtering
pcap-toolkit export --filter "tcp and dst port 443 and src net 10.0.0.0/8" traffic.pcap
```

> Commands and flags are illustrative — see `pcap-toolkit --help` for the authoritative reference as the CLI stabilises.

## Configuration

All options are available as CLI flags or in a TOML config file for repeatable pipelines:

```toml
# pcap-toolkit.toml

[[input]]
path = "captures/*.pcap"

[sort]
enabled = true
slice   = "1h"

[filter]
proto        = ["tcp", "udp"]
dst_port     = [443, 80]
src_ip       = ["10.0.0.0/8"]
unidirectional = false   # bidirectional flow IDs (default)

[[output]]
format = "parquet"
path   = "out/traffic.parquet"
compress_payload = true

[[output]]
format = "json"
path   = "out/traffic.json"

[replay]
interface = "eth0"
speed     = 1.0
```

CLI flags take precedence over the config file.

## Installation

One-liner (Linux / macOS / WSL):

```sh
curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash
```

`cargo install pcap-toolkit`, Nix, and source builds are also supported.
See [docs/Install.md](docs/Install.md) for all install methods, options, and
supported platforms.
