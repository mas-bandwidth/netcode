# netcode-rust
[![](http://meritbadge.herokuapp.com/netcode)](https://crates.io/crates/netcode)
![](https://docs.rs/netcode/badge.svg)

Rust implementation of [netcode.io](https://github.com/networkprotocol/netcode.io).

Currently this repo contains a wrapper for the C API and a pre-alpha pure-rust implemenation.

## Installation

Make sure that libsodium is available on your path or pointed to by SODIUM_LIB_DIR with SODIUM_STATIC=1 for libsodium-sys.
