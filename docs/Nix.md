# Nix Development Guide

This project uses Nix Flakes to provide a fully reproducible development environment. By using Nix, you don't need to manually install Rust, Clippy, or specialized tools like gitleaks — Nix handles it all.

This is a guide aimed at new Nix users in order to ease Nix usage.

## 1. Prerequisites

You must have Nix installed on your system with Flakes and Nix Command enabled.

### On NixOS

```nix
# /etc/nixos/configuration.nix
{ pkgs, ... }: {
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # Recommended: Install direnv for the seamless experience mentioned below
  environment.systemPackages = [ pkgs.direnv ];
}
```

After updating, run `sudo nixos-rebuild switch`.

### On another Linux distribution

Install Nix:

```bash
curl -L https://nixos.org/nix/install | sh
```

Enable Flakes by adding the following to `~/.config/nix/nix.conf` (or `/etc/nix/nix.conf`):

```
experimental-features = nix-command flakes
```

## 2. Entering the Development Shell

To activate the environment, run the following command in the project root:

```bash
nix develop
```

**What happens next?**
* **Toolchain**: The specific Rust version defined in `rust-toolchain.toml` is downloaded.
* **Dependencies**: Build tools (linker, pkg-config, etc.) are added to your `$PATH`.
* **Hooks**: The `pre-commit` hooks are automatically installed into your `.git/` folder using `prek` (faster implementation).
* **Isolation**: These tools are only available while you are in this shell; they won't clutter your system.

## 3. Automatic Activation (Optional but Recommended)

If you don't want to type `nix develop` every time you enter the directory, use direnv.

1. Install direnv via your package manager.
2. Create an `.envrc` file in this project:

```bash
echo "use flake" > .envrc
direnv allow
```

Now your shell will **automatically** load the Rust environment the moment you `cd` into this folder.

## 4. Available Tools

Once inside the shell, you have access to:

| Tool | Purpose |
|:-----|:--------|
| `cargo` | Rust package manager and build tool |
| `rustfmt` | Code formatter |
| `clippy` | Linter with strict warnings |
| `cargo-nextest` | Faster test runner (replaces `cargo test`) |
| `cargo-llvm-cov` | Coverage instrumentation via LLVM |
| `grcov` | Coverage report formatter (lcov, html, cobertura) |
| `cargo-audit` | Scan dependencies for known vulnerabilities |
| `cargo-deny` | Check licenses, bans, and advisories |
| `cargo-machete` | Detect unused dependencies |
| `cargo-cross` | Cross-compile for other targets |
| `cargo-dist` | Build distributable release artifacts |
| `just` | Command runner (see `justfile` for shortcuts) |
| `gitleaks` | Secret scanner for security |
| `prek` | Manages git hooks for linting/formatting |
| `nil` | Nix language server (used by the VSCodium extension) |
| `jaq` | JSON processor (used by the coverage scripts) |
| `codium` | VSCodium with all extensions pre-installed |

## 5. Publishing your package

Once your Rust project is ready, you have two main paths to "publish" it so others can use your tool via Nix.

### Option A: Self-Publishing via your Flake (The Fast Way)

Since you already have a `flake.nix` that defines `packages.default`, other users don't need to wait for a central registry. They can build or run your tool directly:

1. **Commit and push** your changes (including `Cargo.lock`) to your git remote.
2. **Run remotely**: Anyone can now run your binary without installing anything:

```bash
nix run git+https://codeberg.org/YOUR_USERNAME/MY_PROJECT.git
```

3. **Add as an input**: Other Nix users can add your project to their own flakes:

```nix
inputs.my-rust-app.url = "git+https://codeberg.org/YOUR_USERNAME/MY_PROJECT.git";
```

### Option B: Submitting to nixpkgs (The Official Way)

To get your package into the official NixOS/nixpkgs repository (so users can do `nix-env -iA my-package`), follow these steps:

1. **Check criteria**: Ensure your project has a clear license and a tagged release (e.g., `v0.1.0`).
2. **Create a derivation**: Use `buildRustPackage`. It requires a `cargoHash` (which you get by running the build once and letting it fail with the correct hash).

```nix
# Example snippet for nixpkgs
MY_PROJECT = rustPlatform.buildRustPackage {
    pname = "MY_PROJECT";
    version = "0.1.0";
    src = fetchFromGitea {
      domain = "codeberg.org";
      owner = "YOUR_USERNAME";
      repo = "MY_PROJECT";
      rev = "v0.1.0";
      hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    };
    cargoHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
};
```

3. **Submit a Pull Request**: Follow the Nixpkgs Contributing Guide. Once merged, your project will be searchable at search.nixos.org/packages.

## 6. Troubleshooting

#### "Command not found: nix"

Ensure you have restarted your shell after the Nix installation or sourced your profile:

```bash
. ~/.nix-profile/etc/profile.d/nix.sh
```

#### "Lockfile version mismatch"

If you update the `flake.nix` inputs, run `nix flake update` to refresh the `flake.lock` file.

#### "Pre-commit failed"

If a commit is blocked, read the error message. Usually it's just `rustfmt` fixing your code. Run `git add .` and try the commit again.
