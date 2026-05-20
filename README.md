<!--
  SETUP CHECKLIST — visible only in your editor, not in the rendered README.
  Complete these before publishing:

  [ ] Replace every MY_PROJECT with your project name
  [ ] Replace YOUR_USERNAME with your Codeberg username
  [ ] Fill in SHORT DESCRIPTION (one sentence, shown in search results)
  [ ] Choose a licence: keep the matching LICENCE*.md and delete the other,
      then update Cargo.toml and the badge below
  [ ] Enable Woodpecker CI on Codeberg to activate the CI badge
  [ ] Uncomment the crates.io and docs.rs badges if you publish to crates.io
  [ ] Fill in the Features, Installation, and Usage sections
-->

# MY_PROJECT

[![CI](https://ci.codeberg.org/api/badges/YOUR_USERNAME/MY_PROJECT/status.svg)](https://ci.codeberg.org/YOUR_USERNAME/MY_PROJECT)
<!-- [![crates.io](https://img.shields.io/crates/v/MY_PROJECT.svg)](https://crates.io/crates/MY_PROJECT) -->
<!-- [![docs.rs](https://docs.rs/MY_PROJECT/badge.svg)](https://docs.rs/MY_PROJECT) -->
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)

SHORT DESCRIPTION

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

## Features

- FEATURE 1
- FEATURE 2

## Installation

### Pre-built binaries

Download the latest binary for your platform from the
[releases page](https://codeberg.org/YOUR_USERNAME/MY_PROJECT/releases).

### From crates.io

```sh
cargo install MY_PROJECT
```

### With Nix

```sh
nix run codeberg:YOUR_USERNAME/MY_PROJECT
```

Or add it permanently to your NixOS configuration or home-manager:

```nix
inputs.MY_PROJECT.url = "git+https://codeberg.org/YOUR_USERNAME/MY_PROJECT.git";
```

### From source

```sh
git clone https://codeberg.org/YOUR_USERNAME/MY_PROJECT.git
cd MY_PROJECT
cargo install --path .
```

## Usage

```sh
MY_PROJECT --help
```

<!-- Add concrete usage examples here, e.g.:

```sh
# Example 1
MY_PROJECT do-something --flag value

# Example 2
MY_PROJECT other-command
```
-->

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on submitting issues, feature requests, and merge requests.

To get started locally:

```sh
nix develop        # enter the dev shell (all tools included)
just ci-all        # run the full pipeline before opening a MR
```

No Nix? You need Rust (via [rustup](https://rustup.rs/)) and the tools listed
in `flake.nix`, then `just ci-all` works the same way.

## Roadmap

See [docs/Roadmap.md](docs/Roadmap.md).

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENCE-Apache-2.0.md)
- [MIT License](LICENCE-MIT.md)

at your option.
