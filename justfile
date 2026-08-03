# --- Variables ---
binary_name := "pcap-toolkit"

# Codeberg release config
codeberg_owner := "slundi"
codeberg_repo := "pcap-toolkit"
codeberg_api := "https://codeberg.org/api/v1"

# Targets built locally via `cross` for releases.
# Darwin targets (x86_64/aarch64-apple-darwin) need osxcross and are only built in CI.
release_targets := "x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu"

# --- Development ---

# Build the project in debug mode
build:
    cargo build

# Run the project
run *args:
    cargo run -- {{args}}

# Watch for changes and run (requires cargo-watch)
watch:
    cargo watch -x run

# --- Quality Control ---

# Run all tests
test:
    cargo nextest run

# Run a full health check (Vulnerabilities, Unused Deps, Licenses)
health-check:
    cargo audit
    cargo machete
    cargo deny check

# Run clippy with strict warnings
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Format all code
fmt:
    cargo fmt --all

# Run all pre-commit hooks manually on all files
check:
    prek run --all-files

# Force update hooks
update-hooks:
    prek autoupdate

# Run gitleaks to scan for secrets
scan-secrets:
    gitleaks detect --verbose --redact

# Check that overall line coverage meets the 80% threshold
# BASE is accepted for interface compatibility with CI (e.g.: just coverage-check master)
coverage-check BASE="master":
    cargo llvm-cov --lcov --output-path lcov.info
    cargo llvm-cov report --fail-under-lines 80

# --- Cleanup ---

# Clean build artifacts
clean:
    cargo clean

# --- CI ---

# Run the complete CI pipeline (use this when already inside `nix develop`)
ci-all: fmt lint test health-check scan-secrets

# Run the complete CI pipeline via Nix devshell — no docker/podman needed
# Equivalent to what Woodpecker and Forgejo Actions run in containers
ci-local:
    nix develop --command just fmt
    nix develop --command just lint
    nix develop --command just test
    nix develop --command just health-check
    nix develop --command just scan-secrets
    @echo "All CI checks passed!"

# Run a quick subset (format + lint + test) — fast feedback loop
ci: fmt lint test
    @echo "Quick checks passed!"

# --- Changelog ---

# Generate or update CHANGELOG.md from conventional commits
changelog:
    git cliff -o CHANGELOG.md
    @echo "CHANGELOG.md updated — commit it before tagging"

# Preview changelog entries for commits not yet in a release
changelog-unreleased:
    git cliff --unreleased

# --- Release ---

# Push an annotated tag without building. Use this once CI handles release uploads.
# Usage: just tag v1.2.3
tag VERSION:
    git tag -a {{VERSION}} -m "Release {{VERSION}}"
    git push origin {{VERSION}}
    @echo "Pushed tag {{VERSION}}"

# Build a release binary for the current platform
build-release:
    cargo build --release

# Build a release binary for a specific cross-compilation target
# Requires `cross` in your PATH (included in flake.nix devShell)
# Usage: just build-release-cross aarch64-unknown-linux-gnu
build-release-cross TARGET:
    cross build --release --target {{TARGET}}

# Assert a musl release binary is fully static (no ELF interpreter, no NEEDED
# libraries) and actually executes. Guards against accidentally reintroducing
# a runtime dependency (e.g. enabling zstd's pkg-config feature). Stronger and
# faster than any container run: if it's static it runs on any Linux.
# Usage: just verify-static x86_64-unknown-linux-musl
verify-static TARGET:
    #!/usr/bin/env bash
    set -euo pipefail
    bin="target/{{TARGET}}/release/{{binary_name}}"
    if readelf -l "$bin" | grep -q INTERP || readelf -d "$bin" 2>/dev/null | grep -q NEEDED; then
        echo "error: $bin is dynamically linked — expected a fully static musl build" >&2
        readelf -d "$bin" 2>/dev/null | grep NEEDED || true
        exit 1
    fi
    "$bin" --version >/dev/null
    echo "  ✓ {{TARGET}} is fully static"

# Build and package a single release artifact into dist/
# Usage: just package v1.2.3 x86_64-unknown-linux-musl
package VERSION TARGET:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p dist
    echo "Building {{binary_name}} {{VERSION}} for {{TARGET}}..."
    cross build --release --target {{TARGET}}
    if [[ "{{TARGET}}" == *-linux-musl ]]; then
        just verify-static {{TARGET}}
    fi
    stage="dist/{{binary_name}}-{{VERSION}}-{{TARGET}}"
    rm -rf "$stage"; mkdir -p "$stage"
    cp README.md LICENSE CHANGELOG.md "$stage/"
    if [[ "{{TARGET}}" == *windows* ]]; then
        cp "target/{{TARGET}}/release/{{binary_name}}.exe" "$stage/"
        (cd dist && zip -qr "{{binary_name}}-{{VERSION}}-{{TARGET}}.zip" "$(basename "$stage")")
    else
        cp "target/{{TARGET}}/release/{{binary_name}}" "$stage/"
        tar -C dist -czf "dist/{{binary_name}}-{{VERSION}}-{{TARGET}}.tar.gz" "$(basename "$stage")"
    fi
    rm -rf "$stage"
    echo "  packaged $(ls dist/{{binary_name}}-{{VERSION}}-{{TARGET}}.*)"

# Build a static MUSL amd64 binary and package it into a .deb (requires cargo-deb).
# Builds natively against the musl target — the flake devShell wires up the musl
# cross compiler, so no `cross`/Docker is needed. Run inside `nix develop`.
# cargo-deb reads package metadata from Cargo.toml. The .deb lands in dist/.
# Usage: just deb
deb:
    #!/usr/bin/env bash
    set -euo pipefail
    target="x86_64-unknown-linux-musl"
    mkdir -p dist
    cargo build --release --target "$target"
    just verify-static "$target"
    # --no-build: package the binary we just built (avoid a redundant rebuild).
    # --no-strip: keep symbols for addr2line on crash reports (see release profile).
    cargo deb --no-build --no-strip --target "$target" --output dist/
    echo "  packaged $(ls dist/*.deb | tail -n1)"

nix-deb:
    nix develop --command just deb

# Build all locally-supported release targets and write SHA256SUMS
# Usage: just package-all v1.2.3
package-all VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f dist/{{binary_name}}-{{VERSION}}-*.tar.gz dist/{{binary_name}}-{{VERSION}}-*.zip dist/{{binary_name}}-{{VERSION}}-SHA256SUMS
    for target in {{release_targets}}; do
        just package {{VERSION}} "$target"
    done
    (cd dist && sha256sum {{binary_name}}-{{VERSION}}-*.tar.gz {{binary_name}}-{{VERSION}}-*.zip 2>/dev/null \
        > {{binary_name}}-{{VERSION}}-SHA256SUMS)
    echo "Artifacts:"
    ls -1 dist/{{binary_name}}-{{VERSION}}-*

# Full release: validate, build all targets, tag + push, create Codeberg release, upload assets.
# Requires CODEBERG_TOKEN env var with write:repository scope
#   (Codeberg → Settings → Applications → Generate New Token).
# Usage: just release v1.2.3
release VERSION: (_release-preflight VERSION) (package-all VERSION)
    just docker-smoke {{VERSION}}
    just _release-tag-push {{VERSION}}
    just _release-codeberg {{VERSION}}
    @echo "✓ Release {{VERSION}} published: https://codeberg.org/{{codeberg_owner}}/{{codeberg_repo}}/releases/tag/{{VERSION}}"

# --- Internal release helpers (prefixed _ to keep `just --list` clean) ---

_release-preflight VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -z "${CODEBERG_TOKEN:-}" ]]; then
        echo "error: CODEBERG_TOKEN not set" >&2
        echo "  Create one at https://codeberg.org/user/settings/applications (scope: write:repository)" >&2
        exit 1
    fi
    if ! git diff-index --quiet HEAD --; then
        echo "error: working tree has uncommitted changes" >&2
        exit 1
    fi
    expected="$(echo {{VERSION}} | sed 's/^v//')"
    actual="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"(.*)".*/\1/')"
    if [[ "$expected" != "$actual" ]]; then
        echo "error: VERSION ($expected) does not match Cargo.toml version ($actual)" >&2
        echo "  Update Cargo.toml + Cargo.lock, commit, then retry." >&2
        exit 1
    fi

_release-tag-push VERSION:
    git tag -a {{VERSION}} -m "Release {{VERSION}}"
    git push origin {{VERSION}}

# Stage Linux release binaries next to the Dockerfile so `docker build` works.
# Pulls from local dist/ if `just package-all VERSION` has been run; otherwise
# fetches the tarballs from the Codeberg release for VERSION.
# Usage: just docker-context v0.2.0
docker-context VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    for pair in "amd64:x86_64-unknown-linux-musl" "arm64:aarch64-unknown-linux-musl"; do
        docker_arch="${pair%%:*}"
        rust_target="${pair##*:}"
        archive="dist/{{binary_name}}-{{VERSION}}-${rust_target}.tar.gz"
        if [[ ! -f "$archive" ]]; then
            echo "fetching ${archive} from Codeberg..."
            mkdir -p dist
            curl -fsSL "https://codeberg.org/{{codeberg_owner}}/{{codeberg_repo}}/releases/download/{{VERSION}}/$(basename "$archive")" \
                -o "$archive"
        fi
        rm -rf "dist/extract-${docker_arch}"
        mkdir -p "dist/extract-${docker_arch}"
        tar -xzf "$archive" -C "dist/extract-${docker_arch}"
        cp "dist/extract-${docker_arch}/{{binary_name}}-{{VERSION}}-${rust_target}/{{binary_name}}" \
            "{{binary_name}}-linux-${docker_arch}"
        rm -rf "dist/extract-${docker_arch}"
    done
    echo "docker build context ready:"
    ls -la {{binary_name}}-linux-*

# Build the distroless release image from local musl artifacts and smoke-test
# it. Because the base is essentially scratch (distroless/static), a passing
# `--version` here proves the binary runs on the most minimal Linux there is —
# a far stronger portability signal than any debian:slim run. Run after
# `just package-all VERSION`.
# Usage: just docker-smoke v1.2.3
docker-smoke VERSION: (docker-context VERSION)
    #!/usr/bin/env bash
    set -euo pipefail
    docker build -t {{binary_name}}:smoke .
    out="$(docker run --rm {{binary_name}}:smoke --version)"
    echo "  ✓ distroless image runs: $out"

_release-codeberg VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    api="{{codeberg_api}}/repos/{{codeberg_owner}}/{{codeberg_repo}}"
    auth="Authorization: token ${CODEBERG_TOKEN}"
    notes="$(git cliff --latest --strip header 2>/dev/null || echo 'See CHANGELOG.md for details.')"
    payload="$(jq -n --arg tag "{{VERSION}}" --arg body "$notes" \
        '{tag_name: $tag, name: $tag, body: $body, draft: false, prerelease: false}')"
    echo "Creating Codeberg release..."
    response="$(curl -sf -X POST -H "$auth" -H "Content-Type: application/json" \
        -d "$payload" "$api/releases")"
    release_id="$(echo "$response" | jq -r '.id')"
    echo "  release id: $release_id"
    for f in dist/{{binary_name}}-{{VERSION}}-*; do
        name="$(basename "$f")"
        echo "  uploading $name"
        curl -sf -X POST -H "$auth" \
            -F "attachment=@$f" \
            "$api/releases/$release_id/assets?name=$name" > /dev/null
    done
