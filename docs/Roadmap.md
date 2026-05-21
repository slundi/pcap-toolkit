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
* [ ] Select and add crates to `[dependencies]`
* [x] Write `AGENT.md` / `CLAUDE.md` to match the project vision
* [ ] Enable Renovate Bot on Codeberg for automated dependency updates (`renovate.json` is ready)

## Phase 1: Foundation & High-Performance Parsing
- [ ] Implement robust PCAP storage container parsing using `pcap-parser`.
- [ ] Integrate `etherparse` for zero-copy extraction of major layers (Ethernet, IPv4, IPv6, TCP, UDP, ICMP).
- [ ] Implement the `info` / `stats` CLI command to retrieve global file boundaries without loading full payloads into RAM.
- [ ] Build a robust TOML-based configuration loading system via `serde` + `toml`.

## Phase 2: Sparse-Indexing, Sorting & Slicing
- [ ] Design the compact 24-byte `PacketIndex` structure to track file offsets and timestamps safely.
- [ ] Implement the **First-Pass** sequence to build and sort the time index in-memory.
- [ ] Implement the **Second-Pass** streaming architecture to write out chronologically sorted PCAPs.
- [ ] Add the time-splitting engine to chunk sorted output files based on configured time intervals (e.g., hourly slices).
- [ ] Enforce Global Header mirroring across all output chunks.

## Phase 3: Traffic Modification (`replay` Engine Enhancements)
- [ ] Implement linear **Time-Shifting** logic to systematically offset timestamps forward or backward.
- [ ] **IP Anonymization & Mapping**: Add features to replace specific IP addresses with target IPs inside packet structures (e.g., `--replace-ip 10.0.0.1=192.168.1.1`).
- [ ] Implement automatic Layer 3 (IP) and Layer 4 (TCP/UDP) **Checksum Recalculation** to guarantee modified packets remain valid for network stacks.

## Phase 4: Structured Data Exporting (SIEM & Data Lakes)
- [ ] Build the structured Key-Value JSON encoder embedding metadata, fully parsed layer elements, and Base64/Hex raw payloads.
- [ ] Integrate **Zstd compression** natively for raw payload storage inside JSON schemas.
- [ ] Implement a partial payload slicing option (`--max-payload-bytes`) to optimize ingestion storage footprints.
- [ ] Implement native columnar **Apache Parquet** and **Apache Avro** format exporters using `Rayon` worker pools.

## Phase 5: Advanced Optimization & Scaling
- [ ] Parallelize packet parsing and export serialization pipelines using a single-producer, multi-consumer (`SPSC`) threading model.
- [ ] Benchmark against `tcpreplay` / `tshark` on massive datasets (10GB+ files).
- [ ] Evaluate basic Flow Tracking (5-tuple conversation grouping) to filter captures by explicit network session history.
