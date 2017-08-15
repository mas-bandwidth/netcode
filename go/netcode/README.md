Implementation of netcode.io for Go
=========================================

This is the main repository for the Go implementation of [netcode.io](https://netcode.io).

## Dependencies
[https://godoc.org/golang.org/x/crypto/chacha20poly1305](https://godoc.org/golang.org/x/crypto/chacha20poly1305). Note that this has been vendored so it should not be necessary to retrieve any packages outside of netcode.

## Testing
To run tests for this package run the following from the package directory:
go test or go test -v

## Updating 
To ensure the package is up-to-date run the following from the package directory:
go get -u

## Documentation
[godocs](https://godoc.org/github.com/networkprotocol/netcode.io/go/netcode/) 

## Author
[Isaac Dawson](https://github.com/wirepair)