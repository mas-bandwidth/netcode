# netcode.io 1.0

**netcode.io** is a simple protocol for creating secure client/server connections over UDP.

## Architecture

There are three main components in a netcode.io-based architecture:

1. The web backend
2. Dedicated servers
3. Clients

The web backend is a typical web server, for example nginx, which authenticates clients and provides a REST API. Clients are endpoints running the netcode.io protocol that want to connect to dedicated server instances. Dedicated servers are instances of the server-side portion of the game or application running in data centers or the cloud.

The sequence of operations for a client connect are:

1. A client authenticates with the web backend
2. The authenticated client requests to play a game via REST call to the web backend
3. The web backend generates a _connect token_ and returns it to that client over HTTPS
4. The client uses the connect token to establish a connection with a dedicated server over UDP
5. The dedicated server runs logic to ensure that only clients with a valid connect token can connect to it
6. Once a connection is established the client and server exchange encrypted and signed UDP packets

## General Conventions

All data in the netcode.io protocol is serialized in a binary format.

Integer values are serialized in little endian byte order.

## Connect Token Structure

A _connect token_ ensures that only authenticated clients who request connection via the web backend can connect to dedicated servers.

The connect token has two parts: private and public.

The private portion of a connect token is encrypted and signed with a private key shared between the web backend and dedicated server instances. 

Prior to encryption the private connect token data has the following binary format.

    [client id] (uint64) // globally unique identifier for an authenticated client
    [num server addresses] (uint32) // in [1,32]
    <for each server address>
    {
        [address type] (uint8) // value of 0 = IPv4 address, 1 = IPv6 address.
        <if IPV4 address>
        {
            // for a given IPv4 address: a.b.c.d:port
            [a] (uint8)
            [b] (uint8)
            [c] (uint8)
            [d] (uint8)
            [port] (uint16)
        }
        <else IPv6 address>
        {
            // for a given IPv6 address: [a:b:c:d:e:f:g:h]:port
            [a] (uint16)
            [b] (uint16)
            [c] (uint16)
            [d] (uint16)
            [e] (uint16)
            [f] (uint16)
            [g] (uint16)
            [h] (uint16)
            [port] (uint16)
        }
    }
    [client to server key] (32 bytes)
    [server to client key] (32 bytes)
    [user data] (256 bytes) // user defined data specific to this protocol id
    <zero pad to 1024 bytes>

This data is variable size but for simplicity it is written to a fixed size buffer of 1024 bytes. Unused bytes are zero padded.

Encryption of the connect token private data is performed using libsodium AEAD primitive *crypto_aead_chacha20poly1305_encrypt* using the following binary data as the _associated data_: 

    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (uint64)          // 64 bit value unique to this particular game/application
    [expire timestamp] (uint64)     // 64 bit unix timestamp when this connect token expires

The nonce for encryption is a 64 bit sequence number that starts at zero and increases with each connect token generated. 

Encryption is performed on the first 1024 - 16 bytes in the buffer only, leaving the last 16 bytes to store the HMAC:

    [encrypted private connect token] (1008 bytes)
    [hmac of private connect token] (16 bytes)

This is referred to as the _encrypted private connect token data_.

Together the public and private data form a _connect token_:

    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (uint64)          // 64 bit value unique to this particular game/application
    [create timestamp] (uint64)     // 64 bit unix timestamp when this connect token was created
    [expire timestamp] (uint64)     // 64 bit unix timestamp when this connect token expires
    [encrypted private connect token sequence] (uint64)
    [encrypted private connect token data] (1024 bytes)
    [num_server_addresses] (uint32) // in [1,32]
    <for each server address>
    {
        [address_type] (uint8) // value of 0 = IPv4 address, 1 = IPv6 address.
        <if IPV4 address>
        {
            // for a given IPv4 address: a.b.c.d:port
            [a] (uint8)
            [b] (uint8)
            [c] (uint8)
            [d] (uint8)
            [port] (uint16)
        }
        <else IPv6 address>
        {
            // for a given IPv6 address: [a:b:c:d:e:f:g:h]:port
            [a] (uint16)
            [b] (uint16)
            [c] (uint16)
            [d] (uint16)
            [e] (uint16)
            [f] (uint16)
            [g] (uint16)
            [h] (uint16)
            [port] (uint16)
        }
    }
    [client to server key] (32 bytes)
    [server to client key] (32 bytes)
    [timeout seconds] (uint32)          // number of seconds with no packets before client times out
    <zero pad to 2048 bytes>

This data is variable size but for simplicity is written to a fixed size buffer of 2048 bytes. Unused bytes are zero padded.

## Packet Structure

...

## Connect Token

## Challenge Token

## Client State Machine

## Server Connection Processing

