# netcode-rust

Rust implementation of [netcode.io](https://github.com/networkprotocol/netcode.io).

Currently this contains a wrapper for the C API and a pre-alpha pure-rust implemenation.

## Installation

Make sure that libsodium is available on your path or pointed to by SODIUM_LIB_DIR with SODIUM_STATIC=1 for libsodium-sys.
Stanard C library include path should be available via INCLUDE env var.