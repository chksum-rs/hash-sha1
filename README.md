# chksum-hash-sha1

[![crates.io](https://img.shields.io/crates/v/chksum-hash-sha1?style=flat-square&logo=rust "crates.io")](https://crates.io/crates/chksum-hash-sha1)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/hash-sha1/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/hash-sha1/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash-sha1?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash-sha1/)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/hash-sha1/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash-sha1/0.0.0/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash-sha1/0.0.0)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/hash-sha1?style=flat-square "LICENSE")](https://github.com/chksum-rs/hash-sha1/blob/master/LICENSE)

An implementation of SHA-1 hash algorithm for batch and stream computation.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-hash-sha1 = "0.0.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash-sha1
```

## Usage

Use the `hash` function for batch digest calculation.

```rust
use chksum_hash_sha1 as sha1;

let digest = sha1::hash(b"example data");
assert_eq!(
    digest.to_hex_lowercase(),
    "efaa311ae448a7374c122061bfed952d940e9e37"
);
```

Use the `default` function to create a hash instance for stream digest calculation.

```rust
use chksum_hash_sha1 as sha1;

let digest = sha1::default()
    .update("example")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "041fa30bf932ae251b33ef8c554be33bb819e380"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash-sha1/).

## License

This crate is licensed under the MIT License.
