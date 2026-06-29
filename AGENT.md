# Agent Context: pcap-toolkit

## Project Identity

**pcap-toolkit** is a blazing-fast, data-oriented PCAP manipulation, routing, and transformation CLI tool written in Rust. It bridges the gap between network engineering and data science by providing high-performance inspection, sorting, splitting, and export of raw packet captures into modern data pipelines (JSON, Parquet, Avro, Elasticsearch).

- **Primary target**: Linux (x86_64, aarch64); Windows and macOS supported via CI
- **Type**: CLI + library
- **Crates.io**: internal only (not yet published)

---

## Project Structure

```
.
├── src/
│   ├── main.rs          # Binary entry point — keep thin, delegate to lib
│   ├── lib.rs           # Library root — public API surface
│   └── ...              # Add modules here (see Code Organisation below)
├── tests/               # Integration tests (black-box, use the public API)
├── benches/             # Criterion benchmarks
├── examples/            # Runnable usage examples (`cargo run --example <name>`)
├── docs/                # Project documentation (Roadmap.md, CLI.md, Nix.md)
├── .cargo/config.toml   # Cargo aliases and linker config (mold)
├── .forgejo/            # Issue/PR templates for Codeberg
├── .github/workflows/   # GitHub Actions: CI (rust.yaml), release (release.yaml), audit, cross_compile
├── .woodpecker.yml      # Woodpecker CI (mirrors Forgejo Actions CI jobs)
├── Cargo.toml           # Package manifest — dependencies, profiles, metadata
├── deny.toml            # cargo-deny: licence, advisory, and ban rules
├── cliff.toml           # git-cliff: changelog generation from conventional commits
├── bacon.toml           # bacon: background check/clippy/test jobs
├── justfile             # Task runner — always use `just <recipe>` over raw cargo
├── flake.nix            # Nix devShell (all tools) + packages.default (nix build/run)
└── shell.nix            # Thin shim delegating to flake.nix (for nix-shell users)
```

---

## Available Commands

Always use `just` recipes rather than raw `cargo` commands.

### Daily development
| Command | Description |
|---------|-------------|
| `just build` | Debug build |
| `just run [ARGS]` | Run the binary |
| `just test` | Run tests with cargo-nextest |
| `just lint` | `cargo clippy --all-targets --all-features -- -D warnings` |
| `just fmt` | `cargo fmt --all` |
| `just watch` | Rebuild on file changes |

### Quality
| Command | Description |
|---------|-------------|
| `just ci` | Quick pipeline: fmt + lint + test |
| `just ci-all` | Full pipeline: fmt + lint + test + health-check + scan-secrets |
| `just ci-local` | Full pipeline via `nix develop` (no prior shell entry needed) |
| `just health-check` | `cargo audit` + `cargo machete` + `cargo deny check` |
| `just coverage-check` | Run llvm-cov and fail if line coverage < 80% |
| `just scan-secrets` | gitleaks secret scan |

### Release
| Command | Description |
|---------|-------------|
| `just changelog` | Regenerate `CHANGELOG.md` from conventional commits |
| `just changelog-unreleased` | Preview unreleased entries |
| `just tag v1.2.3` | Create annotated tag and push → triggers release workflow |
| `just build-release` | Native release binary |
| `just build-release-cross TARGET` | Cross-compile via `cross` |

---

## Technical Standards

### Language and edition
- Rust edition **2024** (requires ≥ 1.85)
- Stable toolchain only — no nightly features

### Safety
- **No `unsafe` code** without explicit written justification in a comment
- **No `unwrap()` or `expect()`** in library code — propagate errors with `?`
- `unwrap()` is acceptable only in tests and in `main()` for unrecoverable setup errors

### Error handling
- **`anyhow`** for binary/application errors (ergonomic, no custom types needed)
- **`thiserror`** for library errors (typed, implementors can match on variants)
- Always use `?` to propagate; never silently discard errors with `let _ =`

### Dependencies
- Add with `cargo add <crate>` — do not edit `Cargo.toml` manually for deps
- Check licence compatibility against `deny.toml` before adding; update `[licenses] allow` if needed
- Prefer crates with: recent activity, `no_std` support where relevant, minimal transitive deps
- **Ask before adding** any new dependency — prefer solving with `std` first

### Performance
- Avoid unnecessary allocations in hot paths
- Prefer iterators over index loops
- Profile before optimising — do not guess

---

## Code Organisation

### File size
- If a file exceeds **~500 lines**, split it:
  - Move related functions into a new `mod` (e.g. `src/parser.rs` or `src/parser/mod.rs`)
  - If tests make up > 70% of the file, move them to `tests/<module>_test.rs`

### Module structure
```
src/
├── lib.rs           # re-exports only; no logic here
├── config.rs        # configuration types and parsing
├── error.rs         # custom error types (thiserror)
└── <feature>/
    ├── mod.rs       # public API for the feature
    └── ...
```

### Tests
- **Unit tests**: `#[cfg(test)]` module at the bottom of the file they test
- **Integration tests**: `tests/<name>.rs` — test the public API only, no `use crate::internal`
- **Benchmarks**: `benches/bench.rs` using criterion
- Every public function should have at least one unit test
- Test names: `test_<what>_<expected_outcome>` (e.g. `test_parse_empty_input_returns_error`)

### Documentation
- Every public item (`pub fn`, `pub struct`, etc.) must have a `///` doc comment
- Include an `# Examples` section for non-trivial public functions
- At the top of each file, add a one-line `//!` module doc describing its purpose

---

## Development Workflow

After every change:

1. **Write or update tests** for any new or modified behaviour
2. **Format and lint**: `just fmt && just lint` — fix all warnings before proceeding
3. **Run tests**: `just test`
4. **Full pipeline** (before opening a MR): `just ci-all`
5. **Suggest a commit message** following [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(scope): add X` — new feature
   - `fix(scope): correct Y` — bug fix
   - `refactor(scope): simplify Z` — no behaviour change
   - `test(scope): add tests for W` — tests only
   - `docs(scope): update readme` — documentation only
   - `chore(scope): bump deps` — maintenance
6. **Update `docs/Roadmap.md`**: mark completed items with `[x]`

---

## Do Not

- **Do not** add dependencies without being asked
- **Do not** use `unsafe`
- **Do not** commit directly — suggest commit messages; the human commits
- **Do not** modify CI configuration (`.woodpecker.yml`, `.github/workflows/`) unless explicitly asked
- **Do not** modify `flake.nix` or `Cargo.toml` profiles without being asked
- **Do not** create files outside the established structure without asking
- **Do not** remove or alter existing tests — add new ones instead
- **Do not** use `eprintln!` or `println!` for logging in library code — use the `log` crate facade
- **Do not** leave `TODO` or `FIXME` comments in committed code — resolve them or open an issue

---

## CI and Release

### CI (runs on every push and pull request)
- **Woodpecker** (`.woodpecker.yml`): lint → test → security → coverage
- **Forgejo Actions** (`.github/workflows/rust.yaml`): mirrors the same jobs

Both call `just` recipes, so local and CI behaviour are identical.

### Release process
```sh
just changelog            # update CHANGELOG.md
git add CHANGELOG.md
git commit -m "chore(release): prepare for vX.Y.Z"
just tag vX.Y.Z           # push tag → triggers .github/workflows/release.yaml
```
The release workflow cross-compiles for Linux, macOS, and Windows and uploads
binaries to the Forgejo/GitHub release automatically.

---

## Knowledge Base

- **Roadmap**: docs/Roadmap.md
- **CLI reference**: docs/CLI.md
- **Nix setup**: docs/Nix.md
