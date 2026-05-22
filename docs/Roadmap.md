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

- [x] Support `--not` prefix to negate any single filter rule.
- [x] Multiple rules of the same type are OR-ed by default (e.g. two `--src-ip` rules keep packets matching either).
- [x] Rules of different types are AND-ed (protocol AND ip AND port must all match).
- [x] TOML config supports explicit `[[filter.rules]]` blocks with an `op = "and|or|not"` field for full boolean control.

### BPF Expression Filter

Syntax: tcpdump/libpcap style (`"tcp and dst port 443 and src net 10.0.0.0/8"`).
Rationale for choosing BPF over Wireshark display-filter syntax:
- BPF is the de-facto CLI standard; tcpdump users know it from muscle memory.
- Wireshark display filter syntax is GUI-oriented and offers no capability that the
  structured flags (`--src-ip`, `--proto`, `--dst-port`, …) don't already cover.
- Supporting both would double parser + test surface for zero new power.

Implementation: pure Rust, no C bindings, no `libpcap` linkage.
No maintained pure-Rust cBPF expression evaluator exists on crates.io (`bpf-filter`
and `wirefilter` are absent or unmaintained). `solana_rbpf` is an eBPF VM, not a
cBPF expression parser — it is not applicable here. The implementation is therefore
a hand-written recursive-descent parser that produces an AST, evaluated against the
`PacketMeta` already provided by `etherparse`.

Supported grammar subset (covers >95 % of real-world usage):

```
expr     = or-expr
or-expr  = and-expr  ('or'  and-expr)*
and-expr = not-expr  ('and' not-expr)*
not-expr = 'not' not-expr | '(' expr ')' | primitive
primitive =
    proto-kw                              # tcp | udp | icmp | icmp6 | arp | ip | ip6
  | dir 'host' ip-addr                   # [src|dst] host 1.2.3.4
  | dir 'net'  cidr                      # [src|dst] net 10.0.0.0/8
  | dir 'port' port-or-range             # [src|dst] port 443 | port 1024-65535
  | 'proto' proto-num                    # proto 17
  | 'len' cmp-op number                  # len > 100 | len <= 1500
  | 'tcp[tcpflags]' cmp-op flags-expr   # tcp[tcpflags] & (tcp-syn|tcp-ack) != 0
dir      = 'src' | 'dst' | 'src or dst' | 'src and dst' | ε  (default = src or dst)
```

- [x] Implement the recursive-descent parser for the grammar above.
  Use a hand-rolled tokeniser (no parser-combinator crate needed for this size).
- [x] Define `BpfExpr` AST enum and `eval(expr, meta) -> bool` function
  that delegates to the same `IpNet`, `PortRange`, `TcpFlagsFilter` types used by
  the structured filters.
- [x] Wire `--filter <expr>` CLI flag into `SortArgs`; parse at startup and store
  a compiled `BpfExpr` in `SortOptions`.
- [x] AND the BPF result with the structured filter result in the second pass
  (`filter.matches(meta) && bpf_expr.eval(meta)`).
- [x] Return a clear parse error (with column offset) if the expression is invalid.
- [ ] First-pass optimisation (future): inspect the AST at startup and skip indexing
  packets that cannot match (e.g. wrong link-layer type, wrong IP version).

## Phase 4: Traffic Modification

Packet-level transformations applied during the second pass before writing or replaying.

- [x] **Payload Truncation**: `--max-payload-bytes N` — keep only the first N bytes of each packet's payload (preserves Ethernet + IP + transport headers). Useful for reducing storage while retaining all header metadata for analysis.
- [x] **Timestamp Shifting**: accept a target start datetime (ms epoch) and shift all timestamps by the computed delta so the capture starts at the requested time.
- [x] **IP Address Mapping**: replace IP addresses in packet headers according to a mapping table (e.g. `--replace-ip 10.0.0.1=192.168.1.1`), configurable in TOML.
  - Same address-family replacements (IPv4→IPv4, IPv6→IPv6) are straightforward.
  - Cross-family mapping (IPv4↔IPv6) is supported: the entire Ethernet payload is re-framed and all checksums recomputed.
- [x] **Checksum Recalculation**: after any header modification, recompute Layer 3 (IP) and Layer 4 (TCP/UDP) checksums to keep packets valid for network stacks and replay targets.

## Phase 5: Structured Data Export (SIEM & Data Lakes)

Turn raw packets into queryable columnar or document data.

- [x] **JSON export**: one JSON object per packet embedding parsed layer fields, flow ID, flow metadata, and raw payload encoded as Base64. Output is JSONL (newline-delimited JSON, `.jsonl`).
- [x] **Payload compression**: optional Zstd compression of the raw payload field (JSON: per-field `zstd+base64`; Parquet: ZSTD column compression; Avro: file-level ZSTD codec). Enabled via `--compress-payload`.
- [x] **Apache Parquet export**: columnar output using a typed schema (timestamp_ns INT64, IPs as STRING, ports/protocol/flags INT32, flow_id INT64, payload BYTE_ARRAY). Uses `parquet` crate with SNAPPY (default) or ZSTD column compression.
- [x] **Apache Avro export**: schema-first encoding using `apache-avro`; the Avro schema (`.avsc`) is written alongside the data file for self-describing datasets. Supports ZSTD codec.
- [x] Wire all export formats to the TOML config (`[export]` table: `path`, `format`, `compress_payload`, `unidirectional`) and CLI (`export` subcommand with full filter flag parity with `sort`).

## Phase 6: Live Replay

Send a (possibly filtered, modified, sorted, or time-shifted) capture onto a real network interface.

- [x] Implement the `replay` command: read packets from the second-pass pipeline and transmit them via a raw socket (`socket2` + `AF_PACKET` on Linux).
- [x] Honour original inter-packet timing or support a speed multiplier (`--speed 2.0`, `--speed max`).
- [x] Paquet per second `--pps 4096` that will ignore previous inter-packet timing.
- [x] Accept replay interface from CLI flag or TOML config.
- [x] Graceful permission check: detect missing `CAP_NET_RAW` and emit a clear error.

## Phase 7: Performance & Scale

- [ ] 7.1 Benchmark against `tcpreplay` / `tshark` on large datasets (1 GB, 10 GB, 100 GB).
- [x] 7.2 Parallelise the first-pass index build across multiple input files using `Rayon`.
- [x] 7.3 Channel-based streaming export: `PacketSink` trait + `JsonSink`/`ParquetSink`/`AvroSink`; producer thread reads and filters PCAP, main thread serialises via bounded `sync_channel`; eliminates `Vec<PacketRecord>` accumulator.
- [x] 7.4 First-pass pre-filter: skip indexing packets that cannot match active structured filters (protocol, IP, port checks are cheap at index time).
- [ ] 7.5 Profile and optimise hot paths with `perf` / `flamegraph` before committing to any architectural change.

## Ideas & Future Work

Items not yet scoped — open for discussion before implementation.

- [x] **IPv4 ↔ IPv6 cross-family IP mapping**: replacing an IPv4 address with an IPv6 one (or vice versa) changes the Ethernet payload size and requires re-framing the entire packet. Unmapped IPv4 addresses are embedded as `::ffff:a.b.c.d`; unmapped IPv6 addresses that are not IPv4-mapped cause the re-frame to be skipped. `orig_len` and `caplen` are updated to reflect the new frame size.
- [x] **Per-protocol truncation rules in TOML**: e.g. keep 128 bytes for TCP/HTTP but only 64 bytes for UDP/DNS, letting users tune storage vs. fidelity per traffic type.
- [ ] **PCAPng support**: extended block types (EPB, ISB, NRB) for richer metadata and multi-interface captures.
- [ ] **Streaming input**: read from a live capture interface (`libpcap`) or a named pipe in addition to files, enabling use as a processing stage in a pipeline.
- [ ] **Flow count threshold filter**: only include flows with ≥ N packets, filtering out noise and single-packet anomalies.
- [ ] **Payload content filter**: byte pattern or regex match inside the packet payload. Powerful for finding specific application-layer markers but costly — evaluate impact before implementing.
- [ ] **zstd compression on RAW data**: (examples: Apache Parquet + Zstd (standard), Apache Avro + Zstd (The Streaming Choice))

- **I/O buffer tuning**: `BufWriter` is already used in the JSON and PCAP sort writers, but both use the default 8 KB internal capacity. At 8 KB, the JSON writer flushes roughly every 20–40 packet records; the PCAP sort writer flushes every 5–130 packets depending on frame size. Both should be raised to `BufWriter::with_capacity(64 * 1024, file)` (64 KB), cutting write syscalls by ~8×. The Parquet and Avro writers write directly to `File` without a `BufWriter`, which is intentional: the `parquet` crate buffers internally per row group (4 096 rows) and `apache-avro` buffers per Avro block — adding a second layer would double-buffer with no gain. The only actionable change is adjusting the two explicit `BufWriter::new(…)` call sites.

- **Multiple simultaneous outputs (fan-out export)**: currently `export_file()` in `src/export/mod.rs` makes two passes over the data — one to collect a `Vec<PacketRecord>` in RAM, then one dispatch to a single writer. For large captures this means the entire packet set lives in memory and a second run is needed to produce a different format. The fix is a streaming, multi-sink pipeline:

  **`PacketSink` trait** — a common push interface for all format writers:
  ```rust
  pub trait PacketSink {
      fn write(&mut self, record: &PacketRecord) -> Result<(), ExportError>;
      fn close(&mut self) -> Result<u64, ExportError>; // returns packet count
  }
  ```
  Concrete impls:
  - `JsonSink` — wraps `BufWriter<File>` (64 KB), writes one JSONL line per `write()` call.
  - `ParquetSink` — accumulates an internal `Vec<PacketRecord>` of up to `BATCH_SIZE` (4 096) rows; flushes a row group in `write()` when full, flushes the remainder in `close()`. The underlying `SerializedFileWriter<File>` stays unwrapped.
  - `AvroSink` — thin wrapper around `apache_avro::Writer<File>`; calls `append_ser()` per record, `flush()` in `close()`. The underlying `Writer` is unwrapped.
  - `PcapSink` — wraps `SlicedWriter` for round-trip PCAP output with optional time-slicing. (Useful for `sort` fan-out, see below.)

  **`MultiExportOptions`** — replaces the single-path `ExportOptions`:
  ```rust
  pub struct OutputTarget {
      pub path:             PathBuf,
      pub format:           Option<ExportFormat>, // None → infer from extension
      pub compress_payload: bool,
  }

  pub struct MultiExportOptions {
      pub targets:       Vec<OutputTarget>,
      pub filter:        Filter,
      pub bpf_filter:    Option<BpfExpr>,
      pub unidirectional: bool,
  }
  ```

  **Streaming loop** in `export_multi()`:
  ```
  open pcap → for each packet:
      build PacketMeta → apply filter → build PacketRecord →
          for sink in &mut sinks { sink.write(&record)?; }
  for sink in sinks { sink.close()?; }
  ```
  No `Vec<PacketRecord>` accumulator. Memory usage is O(buffer sizes) — fixed overhead regardless of capture size.

  **CLI**: the `export` subcommand gains `--output` as a repeatable flag:
  ```
  pcap-toolkit export capture.pcap \
      --output out.jsonl \
      --output out.parquet \
      --output out.avro
  ```
  TOML gains an `[[export.outputs]]` array replacing the single `[export]` table.

  **Sort fan-out**: `SortOptions` gains an optional `Vec<OutputTarget>` so a sorted pass can simultaneously write the sorted PCAP *and* a JSONL/Parquet export without a second read.

  **Backward compatibility**: `ExportOptions` (single output) is kept as a thin wrapper that constructs a `MultiExportOptions` with one target, so existing code paths and tests are unaffected.

- **replay on multiple interfaces**
