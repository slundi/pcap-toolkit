#!/usr/bin/env bash
# pcap-toolkit installer
#
# Downloads a release binary from Codeberg for the current platform and
# installs it. Defaults to a user-local install (~/.local/bin).
#
#   curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash
#   curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --system
#   curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --version v0.2.0
set -euo pipefail

OWNER="slundi"
REPO="pcap-toolkit"
BIN="pcap-toolkit"
API="https://codeberg.org/api/v1/repos/${OWNER}/${REPO}"

VERSION=""
PREFIX=""
MODE="user"

usage() {
    cat <<EOF
Usage: install.sh [--user | --system | --prefix DIR] [--version vX.Y.Z]

  --user             Install to \$HOME/.local/bin (default; no sudo)
  --system           Install to /usr/local/bin (uses sudo if needed)
  --prefix DIR       Install the binary into DIR
  --version vX.Y.Z   Install a specific release tag instead of the latest
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)    MODE="user"; shift ;;
        --system)  MODE="system"; shift ;;
        --prefix)  MODE="prefix"; PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --version) VERSION="${2:?--version needs a tag}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$MODE" in
    user)   PREFIX="${HOME}/.local/bin" ;;
    system) PREFIX="/usr/local/bin" ;;
    prefix) : ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not installed" >&2; exit 1; }; }
need curl
need tar
need uname

# --- Detect platform -> Rust target triple matching release artifacts ---
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    Linux)
        case "$arch" in
            x86_64|amd64)  target="x86_64-unknown-linux-musl" ;;
            aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
            *) echo "error: unsupported Linux arch: $arch" >&2; exit 1 ;;
        esac
        ext="tar.gz"
        ;;
    Darwin)
        case "$arch" in
            x86_64) target="x86_64-apple-darwin" ;;
            arm64)  target="aarch64-apple-darwin" ;;
            *) echo "error: unsupported macOS arch: $arch" >&2; exit 1 ;;
        esac
        ext="tar.gz"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        target="x86_64-pc-windows-gnu"
        ext="zip"
        need unzip
        ;;
    *)
        echo "error: unsupported OS: $os" >&2
        echo "  Supported: Linux, macOS, Windows (via MSYS/Cygwin/Git Bash)" >&2
        exit 1
        ;;
esac

# --- Resolve version ---
if [[ -z "$VERSION" ]]; then
    echo "Looking up latest release..."
    VERSION="$(curl -fsSL "${API}/releases/latest" \
        | grep -m1 '"tag_name"' \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    if [[ -z "$VERSION" ]]; then
        echo "error: could not determine latest release tag" >&2
        exit 1
    fi
fi
echo "Installing ${BIN} ${VERSION} for ${target}"

asset="${BIN}-${VERSION}-${target}.${ext}"
url="https://codeberg.org/${OWNER}/${REPO}/releases/download/${VERSION}/${asset}"
sums_url="https://codeberg.org/${OWNER}/${REPO}/releases/download/${VERSION}/${BIN}-${VERSION}-SHA256SUMS"

# --- Download + verify ---
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${url}"
if ! curl -fsSL --retry 3 -o "${tmp}/${asset}" "$url"; then
    echo "error: download failed. Check that the asset exists for ${VERSION}/${target}." >&2
    echo "  Browse releases: https://codeberg.org/${OWNER}/${REPO}/releases" >&2
    exit 1
fi

if curl -fsSL --retry 3 -o "${tmp}/SHA256SUMS" "$sums_url" 2>/dev/null; then
    echo "Verifying checksum..."
    expected="$(grep " ${asset}\$" "${tmp}/SHA256SUMS" | awk '{print $1}')"
    if [[ -z "$expected" ]]; then
        echo "warning: ${asset} not listed in SHA256SUMS; skipping verification" >&2
    else
        if command -v sha256sum >/dev/null 2>&1; then
            actual="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
        else
            actual="$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')"
        fi
        if [[ "$expected" != "$actual" ]]; then
            echo "error: checksum mismatch for ${asset}" >&2
            echo "  expected: $expected" >&2
            echo "  actual:   $actual" >&2
            exit 1
        fi
        echo "  ok"
    fi
else
    echo "warning: SHA256SUMS not found for this release; skipping verification" >&2
fi

# --- Extract ---
echo "Extracting..."
if [[ "$ext" == "zip" ]]; then
    unzip -q "${tmp}/${asset}" -d "${tmp}/extract"
else
    mkdir -p "${tmp}/extract"
    tar -xzf "${tmp}/${asset}" -C "${tmp}/extract"
fi

# Archives contain a single dir <bin>-<version>-<target>/ with the binary inside.
src_bin="$(find "${tmp}/extract" -type f \( -name "${BIN}" -o -name "${BIN}.exe" \) | head -n1)"
if [[ -z "$src_bin" ]]; then
    echo "error: binary not found in archive" >&2
    exit 1
fi

# --- Install ---
mkdir -p "$PREFIX" 2>/dev/null || true
dest="${PREFIX}/$(basename "$src_bin")"
echo "Installing to ${dest}"
if [[ -w "$PREFIX" ]] || mkdir -p "$PREFIX" 2>/dev/null; then
    install -m 0755 "$src_bin" "$dest"
else
    echo "  ${PREFIX} not writable; using sudo"
    sudo install -m 0755 "$src_bin" "$dest"
fi

# --- Friendly PATH hint for user-mode installs ---
if [[ "$MODE" == "user" ]] && ! echo ":$PATH:" | grep -q ":${PREFIX}:"; then
    cat <<EOF

Note: ${PREFIX} is not on your PATH. Add this to your shell rc:
  export PATH="${PREFIX}:\$PATH"

EOF
fi

echo "✓ Installed: $("$dest" --version 2>/dev/null || echo "$dest")"
