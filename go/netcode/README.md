Draft Implementation of netcode.io for Go
=========================================

This is the main repository for the Go implementation of [netcode.io](https://netcode.io). This repository and the API are highly violatile until the client and server implementations have been completed.

## Dependencies
codehale's implementation of [chacha20poly130](https://github.com/codahale/chacha20poly1305). While I would have liked to use [https://godoc.org/golang.org/x/crypto/chacha20poly1305](https://godoc.org/golang.org/x/crypto/chacha20poly1305) it only implements the IETF version with nonce size of 12 bytes. Note that this has been vendored so it should not be necessary to retrieve any packages outside of netcode.

## Documentation
[godocs](https://godoc.org/github.com/networkprotocol/netcode.io/go/netcode/) 

## TODO
- Clean up server implementation and write more tests for verifying key/token entries.

## Completed
- Implemented packet and token portion of protocol, verified to work with C server implementation.
- Implemented initial server (still has numerous bugs, but works)
- Implement initial client

## Author
[Isaac Dawson](https://github.com/wirepair)