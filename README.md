solidity-rs
===========
[![Rust: nightly](https://img.shields.io/badge/Rust-nightly-blue.svg)](https://www.rust-lang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) [![Build Status](https://travis-ci.org/Fantom-foundation/solidity-rs.svg?branch=master)](https://travis-ci.org/Fantom-foundation/solidity-rs)

[Solidity](https://github.com/ethereum/solidity) to LLVM implementation in Rust.

## Developer guide

Install the latest version of [Rust](https://www.rust-lang.org). We tend to use nightly versions. [CLI tool for installing Rust](https://rustup.rs).  Also install LLVM-7 development package.

We use [rust-clippy](https://github.com/rust-lang-nursery/rust-clippy) linters to improve code quality.

There are plenty of [IDEs](https://areweideyet.com) and other [Rust development tools to consider](https://github.com/rust-unofficial/awesome-rust#development-tools).

### CLI instructions

```bash
# Install Rust (nightly)
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly
# Install cargo-make (cross-platform feature-rich reimplementation of Make)
$ cargo install --force cargo-make
# Install rustfmt (Rust formatter)
$ rustup component add rustfmt
# Install clippy (Rust linter)
$ rustup component add clippy
# Install llvm-7 development package.
# NB: this command is for Ubuntu 18.04, adjust it according to your system
$ apt install llvm-7-dev
# Clone this repo
$ git clone https://github.com/Fantom-foundation/solidity-rs && cd solidity-rs
# Run tests
$ cargo test
# Format, build and test
$ cargo make
```

### TODO

  [ ] Add support for arbitrary size integers.
  [ ] Add support for arbitrary mantisa floating point numbers.
  [ ] Create a stack of events to push them to once emitted.
  [ ] Add support for dictionaries.
  [ ] Add support for dynamic size arrays.
  [ ] Add support for assembler expressions.
  [ ] Add support for storage specification in functions.
  [ ] Add support for importing other libraries.
  [ ] Add tests.
