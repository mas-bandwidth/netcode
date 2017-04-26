Draft Implementation of netcode.io for Go
=========================================

This is the main repository for the Go implementation of [netcode.io](https://netcode.io). This repository and the API are highly violatile until the client and server implementations have been completed.

## Dependencies
[https://godoc.org/golang.org/x/crypto/chacha20poly1305](https://godoc.org/golang.org/x/crypto/chacha20poly1305). Note that this has been vendored so it should not be necessary to retrieve any packages outside of netcode.

## Documentation
[godocs](https://godoc.org/github.com/networkprotocol/netcode.io/go/netcode/) 

## TODO
- More performance testing, possibly change synchronization method.

## Completed
- Implemented packet and token portion of protocol, verified to work with C server implementation.
- Implemented initial server
- Implement initial client

## Author
[Isaac Dawson](https://github.com/wirepair)