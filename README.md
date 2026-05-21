# pcap-toolkit

[![CI](https://ci.codeberg.org/api/badges/slundi/pcap-toolkit/status.svg)](https://ci.codeberg.org/slundi/pcap-toolkit)
<!-- [![crates.io](https://img.shields.io/crates/v/pcap-toolkit.svg)](https://crates.io/crates/pcap-toolkit) -->
<!-- [![docs.rs](https://docs.rs/pcap-toolkit/badge.svg)](https://docs.rs/pcap-toolkit) -->
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)

A blazing-fast, data-oriented PCAP manipulation, routing, and transformation tool written in Rust.

Unlike traditional tools that treat network captures as static binary blobs, this tool bridges the gap between network engineering and data science. It provides a powerful CLI to inspect, sort, split, and export PCAP data directly into modern data pipelines (Elasticsearch, Parquet, Avro) with native performance.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)

## Features

- **High-Performance `info` & `stats`**: Instant extraction of capture boundaries (start/end timestamps), unique IPs, packet counts, and burst rates without high memory overhead.
- **Two-Pass Chronological Sorting**: Guarantees strict chronological packet ordering using an ultra-lightweight index memory footprint (~24 bytes per packet), preventing TCP session desynchronization during replays.
- **Data-Pipeline Friendly Exporting**: Converts raw PCAP structures into structured Key-Value formats (JSON, Apache Parquet, Apache Avro) with optional high-efficiency **Zstd** payload compression.
- **Smart Time-Shifting & Splitting**: Shift capture timestamps linearly or slice giant PCAP files into distinct, logically organized chronological chunks (e.g., hourly or daily files) on the fly.
- **Engineered for Speed**: Built on a pure CPU-bound parallel processing architecture powered by `Rayon`, fully leveraging modern multi-core systems.

## Architecture & Choices

- **Zero-Copy Parsing**: Combines `pcap-parser` for robust file structure indexation with `etherparse` for blazing-fast network layer parsing.
- **Data-First Focus**: Designed to let Security Data Scientists and Threat Hunters run ultra-fast queries on raw packet structures inside modern SIEMs or data lakes (like DuckDB or Snowflake).

## Installation

### Pre-built binaries

Download the latest binary for your platform from the
[releases page](https://codeberg.org/slundi/pcap-toolkit/releases).

### From crates.io

```sh
cargo install pcap-toolkit
```

### With Nix

```sh
nix run codeberg:slundi/pcap-toolkit
```

Or add it permanently to your NixOS configuration or home-manager:

```nix
inputs.pcap-toolkit.url = "git+https://codeberg.org/slundi/pcap-toolkit.git";
```

### From source

```sh
git clone https://codeberg.org/slundi/pcap-toolkit.git
cd pcap-toolkit
cargo install --path .
```

## Usage

```sh
pcap-toolkit --help
```

<!-- Add concrete usage examples here, e.g.:

```sh
# Example 1
pcap-toolkit do-something --flag value

# Example 2
pcap-toolkit other-command
```
-->
