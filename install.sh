#!/usr/bin/env bash
# pcap-toolkit installer
#
# Downloads a release binary for the current platform and installs it.
# Defaults to a user-local install (~/.local/bin). Assets are fetched from
# Codeberg first, then from the GitHub mirror.
#
#   curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash
#   curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --system
#   curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --deb
#   curl -fsSL https://codeberg.org/slundi/pcap-toolkit/raw/branch/master/install.sh | bash -s -- --version v0.2.0
set -euo pipefail

OWNER="slundi"
REPO="pcap-toolkit"
BIN="pcap-toolkit"
API="https://codeberg.org/api/v1/repos/${OWNER}/${REPO}"
GITHUB_API="https://api.github.com/repos/${OWNER}/${REPO}"

# Release download bases, tried in order. Both forges get the same assets from
# `just release`; GitHub may additionally carry macOS builds.
MIRRORS=(
    "https://codeberg.org/${OWNER}/${REPO}/releases/download"
    "https://github.com/${OWNER}/${REPO}/releases/download"
)

VERSION=""
PREFIX=""
MODE="user"

usage() {
    cat <<EOF
Usage: install.sh [--user | --system | --prefix DIR | --deb] [--version vX.Y.Z]

  --user             Install to \$HOME/.local/bin (default; no sudo)
  --system           Install to /usr/local/bin (uses sudo if needed)
  --prefix DIR       Install the binary into DIR
  --deb              Install the .deb package with apt (Debian/Ubuntu; uses sudo)
  --version vX.Y.Z   Install a specific release tag instead of the latest
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)    MODE="user"; shift ;;
        --system)  MODE="system"; shift ;;
        --prefix)  MODE="prefix"; PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --deb)     MODE="deb"; shift ;;
        --version) VERSION="${2:?--version needs a tag}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$MODE" in
    user)   PREFIX="${HOME}/.local/bin" ;;
    system) PREFIX="/usr/local/bin" ;;
    prefix|deb) : ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not installed" >&2; exit 1; }; }
need curl
need tar
need uname

# Run a command as root: directly when already root (e.g. in a container
# without sudo), through sudo otherwise.
as_root() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    else
        need sudo
        sudo "$@"
    fi
}

# --- Detect platform -> Rust target triple matching release artifacts ---
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    Linux)
        # All Linux builds are fully static musl binaries, so only the CPU
        # matters (a 32-bit userland on a 64-bit kernel runs the 64-bit build).
        case "$arch" in
            x86_64|amd64)  target="x86_64-unknown-linux-musl" ;;
            aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
            i686)          target="i686-unknown-linux-musl" ;;
            armv7l|armv8l) target="armv7-unknown-linux-musleabihf" ;;
            armv6l)        target="arm-unknown-linux-musleabihf" ;;
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

# --- .deb mode: the package arch follows dpkg, not the kernel ---
if [[ "$MODE" == "deb" ]]; then
    if [[ "$os" != "Linux" ]]; then
        echo "error: --deb is only supported on Debian-based Linux" >&2
        exit 1
    fi
    need dpkg
    deb_arch="$(dpkg --print-architecture)"
    case "$deb_arch" in
        amd64|arm64|i386|armhf) : ;;
        *) echo "error: no .deb published for '$deb_arch'; run without --deb" >&2; exit 1 ;;
    esac
    if [[ "$arch" == "armv6l" ]]; then
        echo "error: the armhf .deb is built for ARMv7 and won't run on ARMv6; run without --deb" >&2
        exit 1
    fi
fi

# --- Resolve version ---
latest_tag() {
    curl -fsSL "$1" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}
if [[ -z "$VERSION" ]]; then
    echo "Looking up latest release..."
    VERSION="$(latest_tag "${API}/releases/latest" || true)"
    if [[ -z "$VERSION" ]]; then
        VERSION="$(latest_tag "${GITHUB_API}/releases/latest" || true)"
    fi
    if [[ -z "$VERSION" ]]; then
        echo "error: could not determine latest release tag" >&2
        exit 1
    fi
fi

if [[ "$MODE" == "deb" ]]; then
    # cargo-deb names packages <name>_<version>-<revision>_<arch>.deb (revision 1).
    asset="${BIN}_${VERSION#v}-1_${deb_arch}.deb"
    echo "Installing ${BIN} ${VERSION} (.deb, ${deb_arch})"
else
    asset="${BIN}-${VERSION}-${target}.${ext}"
    echo "Installing ${BIN} ${VERSION} for ${target}"
fi

# --- Download + verify ---
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

base=""
for mirror in "${MIRRORS[@]}"; do
    echo "Downloading ${mirror}/${VERSION}/${asset}"
    if curl -fsL --retry 3 -o "${tmp}/${asset}" "${mirror}/${VERSION}/${asset}"; then
        base="${mirror}/${VERSION}"
        break
    fi
    echo "  not available there"
done
if [[ -z "$base" ]]; then
    echo "error: ${asset} is not published for ${VERSION}." >&2
    if [[ "$os" == "Darwin" ]]; then
        echo "  macOS builds are not attached to every release; use \`cargo install pcap-toolkit\` or Nix instead." >&2
    fi
    echo "  Browse releases: https://codeberg.org/${OWNER}/${REPO}/releases" >&2
    exit 1
fi
sums_url="${base}/${BIN}-${VERSION}-SHA256SUMS"

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

# --- .deb install: hand the package to apt (falls back to dpkg) ---
if [[ "$MODE" == "deb" ]]; then
    # Let apt's unprivileged `_apt` user read the file (avoids a sandbox notice).
    chmod 755 "$tmp"
    chmod 644 "${tmp}/${asset}"
    if command -v apt-get >/dev/null 2>&1; then
        as_root apt-get install -y "${tmp}/${asset}"
    else
        as_root dpkg -i "${tmp}/${asset}"
    fi
    echo "✓ Installed: $("/usr/bin/${BIN}" --version 2>/dev/null || echo "/usr/bin/${BIN}")"
    echo "  Uninstall with: sudo apt remove ${BIN}"
    exit 0
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
if [[ -w "$PREFIX" ]]; then
    install -m 0755 "$src_bin" "$dest"
else
    echo "  ${PREFIX} not writable; using sudo"
    as_root mkdir -p "$PREFIX"
    as_root install -m 0755 "$src_bin" "$dest"
fi

# --- Friendly PATH hint for user-mode installs ---
if [[ "$MODE" == "user" ]] && ! echo ":$PATH:" | grep -q ":${PREFIX}:"; then
    cat <<EOF

Note: ${PREFIX} is not on your PATH. Add this to your shell rc:
  export PATH="${PREFIX}:\$PATH"

EOF
fi

echo "✓ Installed: $("$dest" --version 2>/dev/null || echo "$dest")"
