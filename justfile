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

# Build and package a single release artifact into dist/
# Usage: just package v1.2.3 x86_64-unknown-linux-musl
package VERSION TARGET:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p dist
    echo "Building {{binary_name}} {{VERSION}} for {{TARGET}}..."
    cross build --release --target {{TARGET}}
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
