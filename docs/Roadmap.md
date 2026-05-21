# Roadmap

This document outlines the milestones and engineering steps planned for the development of this Rust-based PCAP utility.

## 0 Project setup

* [x] Change project name in `README.md`, `Cargo.toml`, `justfile`, `.github/workflows/release.yaml`
* [x] Choose licence in `Cargo.toml` and keep the matching `LICENCE*.md` at the root
* [x] Update `deny.toml` — adjust the `[licenses] allow` list to match your dependencies
* [ ] Update `SECURITY.md` — fill in contact email / reporting instructions
* [x] Update `Cargo.toml` repository URL
* [ ] Set repository description and topics on Codeberg
* [x] Add 5 keywords and up to 5 categories in `Cargo.toml`
* [x] Set contributing rules in `CONTRIBUTING.md`
* [x] Select and add crates to `[dependencies]`
* [x] Write `AGENT.md` / `CLAUDE.md` to match the project vision
* [ ] Enable Renovate Bot on Codeberg for automated dependency updates (`renovate.json` is ready)

## Phase 1: Foundation — Parsing, Config & Inspection

Core building blocks everything else depends on.

- [x] Integrate `pcap-parser` for robust PCAP/PCAPng file structure handling.
- [x] Integrate `etherparse` for zero-copy layer parsing (Ethernet, IPv4, IPv6, TCP, UDP, ICMP).
- [x] Implement the `info` / `stats` CLI command:
  - Capture start and end timestamps (ms precision).
  - Total packet count and total byte volume.
  - Unique source and destination IPs.
  - Flow table: count packets per 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`.
  - All derived without loading payloads into RAM (streaming, single-pass).
- [x] Design and implement the TOML configuration system (`serde` + `toml`):
  - Input PCAP file(s) or glob pattern.
  - Output targets: file path(s), format, replay interface.
  - Per-command options (truncation, sorting, timestamp shift, IP mapping).
  - Optional per-protocol payload truncation rules.

## Phase 2: Two-Pass Indexing & Chronological Sorting

Designed to handle TB-scale captures without loading everything into RAM.

- [x] Design the `PacketIndex` record (≈ 20 bytes):
  `timestamp_ns: u64`, `byte_offset: u64`, `packet_len: u32`.
- [x] **First Pass — Index Build**: scan PCAP sequentially, emit one `PacketIndex` per packet.
  - In-memory mode: hold the full index in a `Vec` (fast path for files that fit in RAM).
  - On-disk mode: stream the index to a `.idx` sidecar file for TB-scale inputs; the index itself stays small (~20 MB per 1 M packets).
- [x] **Second Pass — Sorted Output / Replay**: sort the index by `timestamp_ns`, then seek and stream packets in order to the output pipeline (write PCAP or feed the replay engine).
- [x] Enforce PCAP Global Header mirroring on all output chunks (link type, snap length, endianness).
- [x] Add time-slicing: split sorted output into separate files by interval (hourly, daily, or custom duration).

## Phase 3: Filtering

Filters are evaluated during the second pass, after sorting, before any output or replay. All filter rules are composable with AND / OR / NOT logic. Rules can be set via CLI flags or TOML config; CLI flags take precedence.

### Flow Identity

- [x] Define a deterministic **Flow ID** computed with `xxh3_64`:
  - **Bidirectional (default)**: canonicalize the two endpoints before hashing so that A→B and B→A share the same ID.
    Canonical form: `sort_lex((src_ip, src_port), (dst_ip, dst_port))` → `(min_ep || max_ep || protocol)`.
  - **Unidirectional**: hash `(src_ip, src_port, dst_ip, dst_port, protocol)` as-is, no reordering.
  - CLI: `--unidirectional` flag. TOML: `[filter] unidirectional = true`.
  - IPs are serialized as fixed-width big-endian bytes (4 bytes for IPv4, 16 bytes for IPv6) before hashing to avoid collisions between address families.

### Structured Filters

- [x] **Protocol**: `--proto tcp,udp,icmp,icmp6,…` — match on IP protocol number or well-known name.
- [x] **IP address / CIDR**:
  - `--src-ip <addr-or-cidr>` — match source IP.
  - `--dst-ip <addr-or-cidr>` — match destination IP.
  - `--ip <addr-or-cidr>` — match either endpoint (logical OR of the above).
  - Accept both exact addresses (`10.0.0.1`, `::1`) and prefix notation (`10.0.0.0/8`, `2001:db8::/32`).
  - IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) normalised to IPv4 before matching.
- [x] **Port**:
  - `--src-port <port-or-range>` — match source port (e.g. `443`, `1024-65535`).
  - `--dst-port <port-or-range>` — match destination port.
  - `--port <port-or-range>` — match either endpoint.
  - Only meaningful for TCP and UDP; silently ignored for other protocols.
- [x] **Flow ID**: `--flow-id <hex>` — include only packets belonging to a specific pre-computed flow ID. Accepts one or more comma-separated values for multi-flow extraction.
- [x] **Time range**: `--from <datetime>` / `--to <datetime>` — retain only packets whose timestamp falls within the window. Datetimes accepted as RFC 3339 (`2024-01-15T14:30:00Z`) or millisecond epoch integers.
- [x] **TCP flags**: `--tcp-flags <mask>` — filter on flag combinations (e.g. `SYN`, `SYN+ACK`, `RST`, `FIN`). Supports `any` (at least one flag set) and `exact` match modes.
- [x] **Packet length**: `--min-len <bytes>` / `--max-len <bytes>` — filter on the captured packet length (after any truncation).

### Logical Composition

- [ ] Support `--not` prefix to negate any single filter rule.
- [ ] Multiple rules of the same type are OR-ed by default (e.g. two `--src-ip` rules keep packets matching either).
- [ ] Rules of different types are AND-ed (protocol AND ip AND port must all match).
- [ ] TOML config supports explicit `[[filter.rules]]` blocks with an `op = "and|or|not"` field for full boolean control.

### BPF Expression Filter

- [ ] `--filter <expr>` — accept a tcpdump/libpcap-style BPF expression (`"tcp and dst port 443 and src net 10.0.0.0/8"`).
- [ ] Evaluate with a **pure-Rust BPF implementation** (no `libpcap` linkage required). Spike task: benchmark available crates and pick the most complete and maintained one. (`solana_rbpf` or `etherparse` + rust code)
- [ ] BPF filter is AND-ed with any structured filters if both are provided.
- [ ] First-pass optimisation (future): parse BPF expression at startup and skip indexing packets that provably cannot match (e.g. wrong link-layer type).

## Phase 4: Traffic Modification

Packet-level transformations applied during the second pass before writing or replaying.

- [ ] **Payload Truncation**: `--max-payload-bytes N` — keep only the first N bytes of each packet's payload (preserves Ethernet + IP + transport headers). Useful for reducing storage while retaining all header metadata for analysis.
- [ ] **Timestamp Shifting**: accept a target start datetime (ms epoch) and shift all timestamps by the computed delta so the capture starts at the requested time.
- [ ] **IP Address Mapping**: replace IP addresses in packet headers according to a mapping table (e.g. `--replace-ip 10.0.0.1=192.168.1.1`), configurable in TOML.
  - Same address-family replacements (IPv4→IPv4, IPv6→IPv6) are straightforward.
  - Cross-family mapping (IPv4↔IPv6) requires re-framing the Ethernet payload and is tracked separately (see Ideas below).
- [ ] **Checksum Recalculation**: after any header modification, recompute Layer 3 (IP) and Layer 4 (TCP/UDP) checksums to keep packets valid for network stacks and replay targets.

## Phase 5: Structured Data Export (SIEM & Data Lakes)

Turn raw packets into queryable columnar or document data.

- [ ] **JSON export**: one JSON object per packet embedding parsed layer fields, flow ID, flow metadata, and raw payload encoded as Base64 or hex.
- [ ] **Payload compression**: optional Zstd compression of the raw payload field inside JSON/Parquet to cut storage significantly.
- [ ] **Apache Parquet export**: columnar output using a typed schema (timestamps, IPs as integers, ports, flags, flow ID, payload bytes). Parallelise row-group encoding with `Rayon`.
- [ ] **Apache Avro export**: schema-first encoding; include the Avro schema file alongside the output for self-describing datasets.
- [ ] Wire all export formats to the TOML config (output path, compression level, schema options).

## Phase 6: Live Replay

Send a (possibly filtered, modified, sorted, or time-shifted) capture onto a real network interface.

- [ ] Implement the `replay` command: read packets from the second-pass pipeline and transmit them via a raw socket (`socket2` or `AF_PACKET` on Linux).
- [ ] Honour original inter-packet timing or support a speed multiplier (`--speed 2.0`, `--speed max`).
- [ ] Accept replay interface from CLI flag or TOML config.
- [ ] Graceful permission check: detect missing `CAP_NET_RAW` and emit a clear error.

## Phase 7: Performance & Scale

- [ ] Benchmark against `tcpreplay` / `tshark` on large datasets (1 GB, 10 GB, 100 GB).
- [ ] Parallelise the first-pass index build across multiple input files using `Rayon`.
- [ ] Evaluate SPSC (single-producer / multi-consumer) channel between the reader and export workers to maximise throughput on multi-core systems.
- [ ] First-pass pre-filter: skip indexing packets that cannot match active structured filters (protocol, IP, port checks are cheap at index time).
- [ ] Profile and optimise hot paths with `perf` / `flamegraph` before committing to any architectural change.

## Ideas & Future Work

Items not yet scoped — open for discussion before implementation.

- **IPv4 ↔ IPv6 cross-family IP mapping**: replacing an IPv4 address with an IPv6 one (or vice versa) changes the Ethernet payload size and requires re-framing the entire packet. Needs a careful design (new `orig_len`, adjusted snap length, possible MTU implications).
- **Per-protocol truncation rules in TOML**: e.g. keep 128 bytes for TCP/HTTP but only 64 bytes for UDP/DNS, letting users tune storage vs. fidelity per traffic type.
- **PCAPng support**: extended block types (EPB, ISB, NRB) for richer metadata and multi-interface captures.
- **Streaming input**: read from a live capture interface (`libpcap`) or a named pipe in addition to files, enabling use as a processing stage in a pipeline.
- **Flow count threshold filter**: only include flows with ≥ N packets, filtering out noise and single-packet anomalies.
- **Payload content filter**: byte pattern or regex match inside the packet payload. Powerful for finding specific application-layer markers but costly — evaluate impact before implementing.
- **zstd compression on RAW data**: (examples: Apache Parquet + Zstd (standard), Apache Avro + Zstd (The Streaming Choice))
- **output/export buffer writer**: BuffWriter from rust. Writing to the disk packet by packet is one of the quickest ways to kill performance.
