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

A _connect token_ ensures that only authenticated clients can connect to dedicated servers.

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

This data is variable size but for simplicity is written to a fixed size buffer of 1024 bytes. Unused bytes are zero padded.

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

## Challenge Token Structure

Challenge tokens are used by netcode.io to stop clients with spoofed IP packet source addresses from connecting to servers.

Prior to encryption, they have the following structure:

    ...
    
Something about encryption.

...

## Packet Structure

**netcode.io** has the following packet types:

* connection request packet (0)
* connection denied packet (1)
* connection challenge packet (2)
* connection response packet (3)
* connection keep alive packet (4)
* connection payload packet packet (5)
* connection disconnect packet packet (6)

The _connection request packet_ (0) is special, as it is not encrypted:

    0 (uint8) // prefix byte of zero
    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (8 bytes)
    [connect token expire timestamp] (8 bytes)
    [connect token sequence number] (8 bytes)
    [encrypted private connect token data] (1024 bytes)
    
All other packet types are encrypted and have the following general format:

    [prefix byte] (uint8) // non-zero prefix byte
    [sequence number] (variable length 1-8 bytes)
    [encrypted packet data] (variable length according to packet type)
    [encrypted packet hmac] (16 bytes)

The prefix byte encodes both the packet type and the number of bytes in the variable length sequence number. The low 4 bits of the prefix byte contain the packet type. The high 4 bits contain the number of bytes for the sequence number in the range [1,8].

The sequence number is encoded by omitting high zero bytes, for example, a sequence number of 1000 is 0x3E8 in hex and requires only three bytes to send its value. Therefore the high 4 bits of the prefix byte are 3 and the sequence data written to the packet after is:

    0x8,0xE,0x3       // sequence bytes reversed for ease of implementation

Encryption of the connect token private data is performed using libsodium AEAD primitive *crypto_aead_chacha20poly1305_encrypt* using the following binary data as the _associated data_: 

    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (uint64)          // 64 bit value unique to this particular game/application
    [expire timestamp] (uint64)     // 64 bit unix timestamp when this connect token expires

Each of the encrypted packet types have their own data that is written to the encrypted packet data portion of the packet.

_connection denied packet_:

    [reason] (uint32)               // currently always 0, which means "server is full".

_connection challenge packet_:

    [challenge token sequence] (uint64)
    [encrypted challenge token data] (360 bytes)
    
_connection response packet_:

    [challenge token sequence] (uint64)
    [encrypted challenge token data] (360 bytes)

_connection keep-alive packet_:

    [client index] (uint32)
    [max clients] (uint32)
    
_connection payload packet_:

    [user payload data] (0 to 1200 bytes)
    
_connection disconnect packet_:
    
    <no data>

## Client State Machine

...

## Server Packet Processing

...

## Replay Protection

...
