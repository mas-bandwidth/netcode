# netcode.io 1.0

**netcode.io** is a simple protocol for creating secure client/server connections over UDP.

## Architecture

There are three main components in a netcode.io-based architecture:

1. The web backend
2. Dedicated servers
3. Clients

The web backend is a typical web server, for example nginx, which authenticates clients and provides a REST API. Clients are endpoints running the netcode.io protocol that want to connect to dedicated server instances. Dedicated servers are instances of the server-side portion of the game or application running on top of netcode.io in data centers or the cloud.

The sequence of operations for a client connect are:

1. A client authenticates with the web backend
2. The authenticated client requests to play a game via a REST call to the web backend
3. The web backend generates a _connect token_ and returns it to the client over HTTPS
4. The client uses the connect token to establish a connection with a dedicated server over UDP
5. The dedicated server runs logic to ensure that only clients with a valid connect token can connect to it
6. Once a connection is established the client and server exchange encrypted and signed UDP packets

## General Conventions

All data in netcode.io protocol is serialized in a binary format.

Integer values are serialized in little endian byte order.

## Connect Token Structure

A _connect token_ ensures that only clients who have authenticated and requested connection via the web backend can connect dedicated servers.

The connect token consists of two parts: private and public.

The private portion is encrypted and signed with a private key known to the web backend and dedicated server instances. 

Prior to encryption the private connect token has the following binary format.

    [client_id] (uint64) // globally unique identifier for an authenticated client
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
    [user data] (256 bytes) // user defined data specific to this protocol id
    <zero pad to 1024 bytes>

The connect token private data is written to a buffer that is 1024 bytes large.

The worst case size is 8 + 4 + 32*(1+8*2+2) + 32 + 32 + 256 = 940 bytes. Unused bytes are zero padded.

Encryption of the connect token private data is performed using libsodium AEAD primitive *crypto_aead_chacha20poly1305_encrypt* using the following binary data as the _associated data_: 

    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (uint64)          // 64 bit value unique to this particular game/application
    [expire timestamp] (uint64)     // 64 bit unix timestamp when this connect token expires

The encryption key is the private key known to the web backend and the dedicated server instances. 

The nonce for encryption is a 64 bit sequence number starting at zero and increasing with each connect token generated. 

Encryption is performed on the first 1024 - 16 bytes, leaving the last 16 bytes in the 1024 byte buffer to store the HMAC:

    [encrypted private connect token] (1008 bytes)
    [hmac of private connect token] (16 bytes)

This is referred to as the _encrypted private connect token data_.

The public portion of the connect token is not encrypted. It provides the client with information it needs to connect to the dedicated server.

Together the public and private portions form a _connect token_:

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
    [timeout seconds] (4 bytes)         // number of seconds with no packets before client conenction times out
    <zero padding to 2048 bytes>

The connect token is written to a buffer that is 2048 bytes large.

The worst case size is 13 + 8 + 8 + 8 + 8 + 1024 + 4 + 32*(1+8*2+2) + 32 + 32 + 4 = 1749 bytes. Unused bytes are zero padded.

This data is sent to the client, typically base64 encoded over HTTPS, because it contains data which should not be exposed to other parties such as the keys used for encrypting UDP packets between the client and the dedicated server.

When the client receives this data, it uses the public portion to know how to connect to a server, and passes the encrypted private connect token data to the dedicated server in the _connection request packet_.

## Packet Structure

...

## Connect Token

## Challenge Token

## Client State Machine

## Server Connection Processing

