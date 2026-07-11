# Command Line Interface (CLI)

`pcap-toolkit` is a high-performance PCAP inspection, filtering, sorting, and
export tool. All functionality is exposed through a single binary with several
subcommands.

## Synopsis

```text
pcap-toolkit [--config <FILE>] <SUBCOMMAND> [OPTIONS]
```

## Global options

| Flag | Type | Description |
|------|------|-------------|
| `-c`, `--config <FILE>` | path | Optional TOML config file. CLI flags override values from the config. |
| `-V`, `--version` | flag | Print the crate version and exit. |
| `-h`, `--help` | flag | Print help for the top-level parser or a subcommand. |

## Subcommands

| Command | Purpose |
|---------|---------|
| [`info`](#info)     | One-line summary of a capture file (packet count, bytes, IP range, timestamps). |
| [`stats`](#stats)   | Per-flow statistics keyed by 5-tuple. Human-readable table or JSON. |
| [`sort`](#sort)     | Sort a capture chronologically (two-pass indexing). Supports filtering, transforms and time-slicing. |
| [`export`](#export) | Export packets to JSON, Parquet or Avro. Supports the same filters as `sort`. |
| [`replay`](#replay) | Replay a capture onto one or more live network interfaces (Linux only, requires `CAP_NET_RAW`). |

---

## `info`

Print a summary of a PCAP capture: packet count, bytes, unique IPs and the
timestamp range.

```text
pcap-toolkit info <INPUT>
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `INPUT` | Input PCAP or PCAPng file. |

### Example

```bash
pcap-toolkit info capture.pcap
```

---

## `stats`

Print per-flow statistics keyed by the canonical 5-tuple.

```text
pcap-toolkit stats [-u|--unidirectional] [--json] <INPUT>
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `INPUT` | Input PCAP or PCAPng file. |

### Options

| Flag | Description |
|------|-------------|
| `-u`, `--unidirectional` | Use unidirectional flow IDs. By default flows are bidirectional (client↔server merged). |
| `--json` | Emit machine-readable JSON instead of the human-readable table. |

### Example

```bash
# Human-readable table, bidirectional flows
pcap-toolkit stats capture.pcap

# Machine-readable JSON, unidirectional flows
pcap-toolkit stats --unidirectional --json capture.pcap | jq .
```

---

## `sort`

Sort a PCAP capture chronologically using a two-pass indexing algorithm.
Accepts one or more inputs (parallel-indexed then merged), applies optional
filters and transforms, and writes either a single sorted file or a directory
of time-sliced files.

```text
pcap-toolkit sort [OPTIONS] -o <OUTPUT> <INPUT>...
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `INPUT...` | One or more input PCAP files. All files are indexed in parallel then merged. **Legacy PCAP only** — PCAPng inputs are rejected. |

### Output options

| Flag | Type | Description |
|------|------|-------------|
| `-o`, `--output <PATH>` | path | **Required.** Output file (no slicing) or directory (with `--slice`). |
| `-s`, `--slice <DURATION>` | duration | Split output by time interval. Accepts `1h`, `30m`, `1d`, `120s`, or a bare number (seconds). Requires `--output` to be a directory. |
| `--on-disk` | flag | Store the packet index in a `.idx` sidecar file instead of RAM. Useful for captures that don't fit in memory. |

### Filter options

Filters within the same category are OR-ed. Categories are AND-ed together.
An empty filter matches every packet.

| Flag | Type | Description |
|------|------|-------------|
| `--proto <PROTOS>` | csv | Protocols to keep. Names (`tcp`, `udp`, `icmp`, `icmp6`) or IP protocol numbers. Comma-separated. |
| `--src-ip <CIDR>` | repeat | Source IP or CIDR to keep. Repeatable, OR-ed. IPv4-mapped IPv6 (`::ffff:A.B.C.D`) is normalised. |
| `--dst-ip <CIDR>` | repeat | Destination IP or CIDR. Same rules as `--src-ip`. |
| `--ip <CIDR>` | repeat | Match either endpoint. |
| `--src-port <PORT>` | repeat | Source port or range (`443`, `1024-65535`). Silently ignored for non-TCP/UDP. |
| `--dst-port <PORT>` | repeat | Destination port or range. |
| `--port <PORT>` | repeat | Match either endpoint. |
| `--flow-id <IDS>` | csv | Comma-separated hex flow IDs (`deadbeef,0xcafe1234`). |
| `--from <DATETIME>` | datetime | Keep packets at or after this timestamp. RFC 3339 or Unix epoch seconds. |
| `--to <DATETIME>` | datetime | Keep packets at or before this timestamp. |
| `--tcp-flags <FLAGS>` | expression | TCP flags filter. `SYN`, `SYN+ACK` (any-mode), `RST:exact` (exact match). |
| `--min-len <BYTES>` | u32 | Minimum captured packet length in bytes. |
| `--max-len <BYTES>` | u32 | Maximum captured packet length in bytes. |
| `-u`, `--unidirectional` | flag | Compute flow IDs unidirectionally (default: bidirectional). |
| `--not` | flag | Invert the entire filter result (keep packets that do **not** match). |
| `-f`, `--filter <EXPR>` | expression | tcpdump/libpcap-style BPF expression, e.g. `"tcp and dst port 443"`. AND-ed with structured filters. |
| `--min-flow-packets <N>` | u64 | Only include flows with at least `N` packets. Triggers a pre-scan pass. Non-IP packets excluded. |

### Transform options

Transforms are applied in a single pass, in this order: IP mapping →
truncation → checksum recalculation. Checksums are recomputed only when
something changed.

| Flag | Type | Description |
|------|------|-------------|
| `--max-payload-bytes <BYTES>` | u32 | Truncate each packet's L4 payload to at most `N` bytes. L2–L4 headers are preserved. |
| `--mtu-trunc <BYTES>` | u32 | Truncate packets so Layer 3 and above is at most `N` bytes (mirrors `tcprewrite --mtu-trunc`). L2 header excluded from the count. |
| `--timestamp-start <DATETIME>` | datetime | Shift all timestamps so the first sorted packet is at this datetime. RFC 3339 or Unix epoch seconds. |
| `--replace-ip <MAPPING>` | repeat | Replace an IP: `OLD_IP=NEW_IP`. Repeatable. Cross-family (IPv4↔IPv6) supported. |

### Examples

```bash
# Simple chronological sort
pcap-toolkit sort -o sorted.pcap in1.pcap in2.pcap

# Sort into hourly slices
pcap-toolkit sort -s 1h -o out_dir/ capture.pcap

# Keep only TCP/443 packets, invert with --not to drop them
pcap-toolkit sort --proto tcp --dst-port 443 --not -o no_https.pcap in.pcap

# Filter with a BPF expression and truncate payloads to 128 B
pcap-toolkit sort \
    -f "tcp and (dst port 443 or dst port 80)" \
    --max-payload-bytes 128 \
    -o web.pcap in.pcap

# Anonymise addresses and shift timestamps
pcap-toolkit sort \
    --replace-ip 10.0.0.1=192.0.2.1 \
    --replace-ip 10.0.0.2=192.0.2.2 \
    --timestamp-start 2026-01-01T00:00:00Z \
    -o anon.pcap in.pcap

# Only keep flows with 10+ packets, using an on-disk index for huge captures
pcap-toolkit sort --min-flow-packets 10 --on-disk -o heavy.pcap huge.pcap
```

---

## `export`

Export PCAP packets to JSON, Parquet or Avro. Filters mirror `sort`. Multiple
`--output` flags fan out to several formats in one pass.

```text
pcap-toolkit export [OPTIONS] [-o <PATH>]... <INPUT>
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `INPUT` | Input PCAP or PCAPng file. |

### Output options

| Flag | Type | Description |
|------|------|-------------|
| `-o`, `--output <PATH>` | repeat | Output file (`.jsonl`, `.parquet`, `.avro`). Repeatable for multi-format fan-out. If omitted (and no output is configured via TOML), JSON is streamed to STDOUT. |
| `-F`, `--format <FMT>` | enum | Override the format of the **first** `--output`: `json`, `parquet`, `avro`. Subsequent outputs infer their format from the extension. |
| `--compress-payload` | flag | Compress payload bytes with Zstd. JSON: per-field base64+zstd; Parquet: column codec ZSTD; Avro: file-level codec `Zstandard`. |

### Filter options

Identical to `sort` — see [Filter options](#filter-options) above. All of the
following are supported: `--proto`, `--src-ip`, `--dst-ip`, `--ip`,
`--src-port`, `--dst-port`, `--port`, `--flow-id`, `--from`, `--to`,
`--tcp-flags`, `--min-len`, `--max-len`, `-u`/`--unidirectional`, `--not`,
`-f`/`--filter`, `--min-flow-packets`.

### Examples

```bash
# Stream JSONL to stdout for piping into jq
pcap-toolkit export capture.pcap | jq -c 'select(.proto == "tcp")'

# Parquet with Zstd-compressed payloads
pcap-toolkit export -o out.parquet --compress-payload capture.pcap

# Fan-out: JSON + Parquet + Avro in one pass
pcap-toolkit export \
    -o packets.jsonl \
    -o packets.parquet \
    -o packets.avro \
    capture.pcap

# Force JSON format despite an unusual extension
pcap-toolkit export -o dump.txt -F json capture.pcap
```

---

## `replay`

Replay a PCAP capture onto one or more live network interfaces.

> **Linux only.** Uses `AF_PACKET + SOCK_RAW`. Requires `CAP_NET_RAW`
> (run as root, `setcap`, or via sudo). Non-Linux platforms return an
> unsupported error.

```text
pcap-toolkit replay [OPTIONS] -i <IFACE>... <INPUT>
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `INPUT` | Input PCAP file to replay. |

### Timing options

| Flag | Type | Description |
|------|------|-------------|
| `-i`, `--interface <IFACE>` | repeat | Network interface to transmit on. Repeatable; each packet is sent to **all** interfaces. |
| `--speed <SPEED>` | string | Replay speed: positive multiplier (`1.0` = real-time, `2.0` = 2× faster, `0.5` = half-speed) or `max` for no inter-packet delay. |
| `--pps <N>` | u64 | Fixed replay rate in packets per second. Mutually exclusive with `--speed`. |

### Filter options

Identical to `sort` and `export` — see [Filter options](#filter-options).

### Examples

```bash
# Real-time replay onto eth0
sudo pcap-toolkit replay -i eth0 capture.pcap

# Fastest possible replay onto two NICs simultaneously
sudo pcap-toolkit replay -i eth0 -i eth1 --speed max capture.pcap

# Constant 10k packets per second
sudo pcap-toolkit replay -i eth0 --pps 10000 capture.pcap

# Replay only TCP SYN packets at 2× speed
sudo pcap-toolkit replay -i eth0 --speed 2.0 \
    --proto tcp --tcp-flags SYN:exact capture.pcap
```

---

## Filter grammar reference

### Protocol names

`tcp` (6), `udp` (17), `icmp` (1), `icmp6` (58). Numeric values are also
accepted, e.g. `--proto 47` (GRE).

### CIDR / IP

Both IPv4 and IPv6 are accepted. Bare addresses are treated as `/32` (v4) or
`/128` (v6). IPv4-mapped IPv6 addresses are normalised, so `10.0.0.0/8`
matches `::ffff:10.x.x.x`.

### Port ranges

- Single port: `443`
- Range: `1024-65535` (inclusive on both ends)

### Datetimes

- RFC 3339 with timezone: `2026-01-01T00:00:00Z`, `2026-01-01T09:00:00+02:00`
- Unix epoch seconds: `1767225600`

### TCP flags

- Any-mode (default): `SYN`, `SYN+ACK`, `RST` — matches when **any** of the
  listed flags are set. Combine with `+`.
- Exact mode: append `:exact` to require the exact flag mask, e.g. `RST:exact`
  matches packets with only `RST` set (no other flags).

### BPF expression (`-f`, `--filter`)

Hand-rolled recursive-descent parser accepting a subset of the tcpdump
grammar:

- Logical: `and`, `or`, `not`, parentheses
- Layer 3: `ip`, `ip6`, `arp`
- Protocol number: `proto <N>`
- Host: `host X`, `src host X`, `dst host X`
- Network: `net X`, `src net X`, `dst net X`
- Ports: `port N`, `src port N`, `dst port N`, ranges via `portrange lo-hi`
- Length: `len > N`, `len < N`, `len = N`, `>=`, `<=`

Example: `tcp and (dst port 443 or dst port 80) and not src net 10.0.0.0/8`

### Flow ID

Bidirectional flow IDs canonicalise the tuple (source/dest sorted lex), so
client→server and server→client packets share the same 64-bit ID. Use
`--unidirectional` to keep them distinct. The IDs printed by `stats` are
suitable input for `--flow-id`.

---

## Configuration file

Any subcommand can consume defaults from a TOML file passed via
`-c`/`--config`. CLI flags override config values. See the top-level
`README.md` and `src/config.rs` for the full schema. Notable sections:

- `[input]` — default input paths.
- `[filter]` — structured filter defaults (mirror the CLI flags), plus
  `[[filter.rules]]` for logical composition (`op = "and"|"or"|"not"`) and
  `min_flow_packets`.
- `[transform]` — `max_payload_bytes`, `timestamp_start`, `replace_ip`, and
  per-protocol rules via `[[transform.truncate_by_proto]]`.
- `[export]` — default `path`, `format`, `compress_payload`,
  `unidirectional`.
- `[replay]` — default `interface`, `speed`, `pps`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success. |
| non-zero | Error. The error message is printed to stderr; specific error variants come from `PcapError`, `ConfigError`, `SortError`, `ExportError`, or `ReplayError`. |
