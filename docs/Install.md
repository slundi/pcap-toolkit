# Installation

`pcap-toolkit` ships pre-built binaries for Linux (x86_64 / aarch64), macOS
(Intel / Apple Silicon), and Windows (x86_64) on the
[Codeberg releases page](https://codeberg.org/slundi/pcap-toolkit/releases).
Source and Nix installs are also supported.

## Quick install (Linux / macOS / WSL / Git Bash)

The repository ships an `install.sh` script that detects your platform,
downloads the matching artifact from Codeberg, verifies the SHA-256 checksum,
and installs the binary.

User install (no `sudo`, drops the binary in `~/.local/bin`):

```sh
curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash
```

System-wide (`/usr/local/bin`, uses `sudo` if required):

```sh
curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --system
```

Pin a specific version:

```sh
curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --version v0.2.0
```

Install into a custom directory:

```sh
curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --prefix /opt/pcap-toolkit/bin
```

### `install.sh` options

| Flag | Effect |
|------|--------|
| `--user` *(default)* | Install to `$HOME/.local/bin`. Prints a `PATH` hint if that directory is not on `PATH`. |
| `--system` | Install to `/usr/local/bin`. Uses `sudo` if the directory is not writable. |
| `--prefix DIR` | Install the binary into `DIR`. |
| `--version vX.Y.Z` | Install a specific release tag instead of the latest. |
| `-h`, `--help` | Show usage and exit. |

If you're piping the script straight from `curl` and you don't trust remote
shell scripts (you shouldn't, by default), download it first and read it
before executing:

```sh
curl -fsSLO https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh
less install.sh
bash install.sh --user
```

### Supported platforms

| OS | Architectures | Artifact |
|----|---------------|----------|
| Linux | `x86_64`, `aarch64` | static MUSL binary (`.tar.gz`) |
| macOS | `x86_64`, `arm64` (Apple Silicon) | `.tar.gz` |
| Windows | `x86_64` | `.zip` (run via MSYS, Cygwin, Git Bash, or WSL) |

## Docker (CI / data pipelines)

Multi-arch images (`linux/amd64`, `linux/arm64`) are published on every
release tag. The image is built `FROM gcr.io/distroless/static-debian12`
with no shell, no package manager, and runs as a non-root user — the
compressed image is around 10 MB.

**Recommended registry — GHCR** (no anonymous pull rate limits):

```sh
docker pull ghcr.io/slundi/pcap-toolkit:latest
docker run --rm -v "$PWD:/data" ghcr.io/slundi/pcap-toolkit:latest info /data/traffic.pcap
```

**Docker Hub mirror** (subject to anonymous pull rate limits — fine for
desktop use, less so for shared CI runners):

```sh
docker pull slundi/pcap-toolkit:latest
```

### Tag scheme

| Tag | Updates on |
|------|-----------|
| `vX.Y.Z` | Pinned to one release. Use this in CI. |
| `X.Y.Z`, `X.Y`, `X` | Floating semver tags. |
| `latest` | Most recent release. Avoid in CI. |

### Live replay from Docker

The default user is non-root, so `replay` (which needs `CAP_NET_RAW` on a
host interface) requires `--cap-add=NET_RAW --user 0 --network host`:

```sh
docker run --rm --cap-add=NET_RAW --user 0 --network host \
  -v "$PWD:/data" ghcr.io/slundi/pcap-toolkit:latest \
  replay --interface eth0 /data/traffic.pcap
```

For pure parse / filter / export workloads no extra flags are needed.

### Building the image locally

```sh
just docker-context v0.2.0      # stage the linux binaries next to the Dockerfile
docker build -t pcap-toolkit:dev .
```

`just docker-context` reuses the tarballs produced by `just package-all`
if they exist, otherwise it downloads them from the Codeberg release for
the given tag.

## Manual download

If you'd rather not run the install script, grab the archive for your
platform directly from the [releases page](https://codeberg.org/slundi/pcap-toolkit/releases),
verify it against the published `pcap-toolkit-<version>-SHA256SUMS` file, and
place the extracted binary somewhere on your `PATH`.

## From crates.io

```sh
cargo install pcap-toolkit
```

Requires a Rust toolchain (`rustup` recommended).

## With Nix

Run without installing:

```sh
nix run codeberg:slundi/pcap-toolkit
```

Or add it to a flake-based NixOS or home-manager configuration:

```nix
inputs.pcap-toolkit.url = "git+https://codeberg.org/slundi/pcap-toolkit.git";
```

See [Nix.md](Nix.md) for a deeper integration guide.

## From source

```sh
git clone https://codeberg.org/slundi/pcap-toolkit.git
cd pcap-toolkit
cargo install --path .
```
