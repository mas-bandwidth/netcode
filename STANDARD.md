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

Encryption of the connect token private data is performed with the libsodium AEAD primitive *crypto_aead_chacha20poly1305_encrypt* using the following binary data as the _associated data_: 

    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (uint64)          // 64 bit value unique to this particular game/application
    [expire timestamp] (uint64)     // 64 bit unix timestamp when this connect token expires

The nonce for encryption is a 64 bit sequence number that starts at zero and increases with each connect token generated. 

Encryption is performed on the first 1024 - 16 bytes in the buffer only, leaving the last 16 bytes to store the HMAC:

    [encrypted private connect token] (1008 bytes)
    [hmac of encrypted private connect token] (16 bytes)

This is referred to as the _encrypted private connect token data_.

Together the public and private data form a _connect token_:

    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (uint64)          // 64 bit value unique to this particular game/application
    [create timestamp] (uint64)     // 64 bit unix timestamp when this connect token was created
    [expire timestamp] (uint64)     // 64 bit unix timestamp when this connect token expires
    [connect token sequence] (uint64)
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

Prior to encryption, challenge tokens have the following structure:

    [client id] (uint64)
    [hmac of encrypted private connect token data] (16 bytes)
    [user data] (256 bytes)
    <zero pad to 300 bytes>
    
Challenge tokens are encrypted with the libsodium _crypto_secretbox_easy_ primitive, with a random key that is generated each time a dedicated server is started and a sequence number that starts at zero and increases with each challenge token generated.

Encryption is performed on the first 300 - 16 bytes, and the last 16 bytes store the HMAC of the encrypted buffer:

    [encrypted challenge token] (284 bytes)
    [hmac of encrypted challenge token data] (16 bytes)
    
Together this is referred to as the _encrypted challenge token data_.

## Packet Structure

**netcode.io** has the following packet types:

* connection request packet (0)
* connection denied packet (1)
* connection challenge packet (2)
* connection response packet (3)
* connection keep alive packet (4)
* connection payload packet packet (5)
* connection disconnect packet packet (6)

The first packet type _connection request packet_ (0) is special, as it is not encrypted:

    0 (uint8) // prefix byte of zero
    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (8 bytes)
    [connect token expire timestamp] (8 bytes)
    [connect token sequence number] (8 bytes)
    [encrypted private connect token data] (1024 bytes)
    
All other packet types are encrypted. Prior to encryption they have the following format:

    [prefix byte] (uint8) // non-zero prefix byte
    [sequence number] (variable length 1-8 bytes)
    [per-packet type data] (variable length according to packet type)

The prefix byte encodes both the packet type and the number of bytes in the variable length sequence number. The low 4 bits of the prefix byte contain the packet type. The high 4 bits contain the number of bytes for the sequence number in the range [1,8].

The sequence number is encoded by omitting high zero bytes, for example, a sequence number of 1000 is 0x3E8 in hex and requires only three bytes to send its value. Therefore the high 4 bits of the prefix byte are set to 3 and the sequence data written to the packet is:

    0x8,0xE,0x3       // sequence bytes reversed for ease of implementation

Each encrypted packet type writes the following data to the per-packet type data section of the packet.

_connection denied packet_:

    <no data>

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

The per-packet type data is encrypted using the libsodium AEAD primitive *crypto_aead_chacha20poly1305_encrypt* with the following binary data as the _associated data_: 

    [version info] (13 bytes)       // "NETCODE 1.00" ASCII with null terminator.
    [protocol id] (uint64)          // 64 bit value unique to this particular game/application
    [prefix byte] (uint8)           // prefix byte in packet. stops an attacker from modifying packet type.

Packets are encrypted with a 64 sequence number that starts at zero and increases with each packet sent. Packets sent from the client to server are encrypted with the client to server key in the connect token for that client. Packets sent from the server to client are encrypted using the server to client key in the connect token for that client.

Post-encryption packets have the following format:

    [prefix byte] (uint8) // non-zero prefix byte
    [sequence number] (variable length 1-8 bytes)
    [encrypted per-packet type data] (variable length according to packet type)
    [hmac of encrypted per-packet type data] (16 bytes)

## Client State Machine

The client has the following states:

* connect token expired (-6)
* invalid connect token (-5)
* connection timed out (-4)
* connection response timed out (-3)
* connection request timed out (-2)
* connection denied (-1)
* disconnected (0)
* sending connection request (1)
* sending connection response (2)
* connected (3)

The initial client state is disconnected (0). Negative states represent error states. The goal state is _connected_ (3).

## Client-Side Connection Process

When a client wants to connect to a server, a _connect token_ is requested from the web backend. 

The client stores this connect token and transitions to the _sending connection request_ state with the first server address in the connect token. The client prepares to encrypt UDP packets sent to the server with the client to server key in the connect token, and decrypt UDP packets received from the server with the server to client key.

While in _sending connection request_ the client sends _connection request packets_ to the server at some rate, like 10HZ. When the client receives a _connection challenge packet_ from the server, it stores the challenge token data and transitions to _sending challenge response_. This represents a successful transition to the next stage in the connection process.

All other transitions from _sending connection request_ are failure cases. In these cases the client first tries to connect to the next server address in the connect token (eg. transitioning to _sending connection request_ state with the next server address in the connect token). Alternatively, when a failure occurs and there are no additional server addresses to connect to, the client transitions to the appropriate error state as described in the next paragraph.

If a _connection request denied_ packet is received while in _sending connection request_ the client transitions to _connection denied_. If neither a _connection challenge packet_ or a _connection denied packet_ are received within the client timeout period specified in the connect token, the client transitions to _connection request timed out_.

While in _sending challenge response_ the client sends _challenge response packets_ to the server at some rate, like 10HZ. When the client receives a _connection keep-alive packet_ from the server, it stores the client index and max clients from the keep-alive packet, and transitions to _connected_. Any _connection payload packets_ received prior to _connected_ are discarded.

All other transitions from _sending challenge response_ are failure cases. In these cases the client first tries to connect to the next server address in the connect token (eg. transitioning to _sending connection request_ with the next server address in the connect token). Alternatively, when a failure occurs and there are no additional servers addresses to connect to, the client transitions to the appropriate error state as described in the next paragraph.

If a _connection request denied_ packet is received while in _sending challenge response_ the client transitions to _connection denied_. If neither a _connection keep-alive packet_ or a _connection denied packet_ are received within the client timeout period specified in the connect token, the client transitions to _challenge response timed out_.

If the entire client connection process takes long enough that the connect token expires before successfully connecting to a server, the client transitions to _connect token expired_. Thus, the connection attempt aborts once the connect token has expired and can no longer possibly succeed, rather than continuing to work through the list of server addresses in the connect token.

While _connected_ the client buffers _connection payload packets_ received from the server so their payloads may be received by the client application. If no _connection payload packet_ or _connection keep-alive packet_ has been received from the server within the client timeout period specified in the connect token, the client transitions to _connection timed out_. 

While _connected_ the client application may send _connection payload packets_ to the server. If no _connection payload packet_ has been sent by the application for some period of time (for example, 1/10th of a second), the client generates and sends _connection keep-alive packets_ to the server at some rate, like 10HZ.

While _connected_ if the client receives a _connection disconnect_ packet from the server, it transitions to _disconnected_.

If the client wishes to disconnect, it sends a number of redundant _connection disconnect packets_ to the server before transitioning to _disconnected_. This informs the server that the client has disconnected and speeds up the disconnection process.

## Server-Side Overview

The dedicated server should be on a publicly accessible IP address and port, without NAT.

The server manages a set of n client slots, where each slot from [0,n-1] represents room for one connected client. The standard does not specify the maximum number of client slots supported by servers, so you may extend this to be any number you wish, provided your implementation can support that many connected clients efficiently.

The server listens on a single UDP socket bound to a specific port. Using this one UDP socket the server multiplexes and demultiplexes packets according to source IP address, negotiates connection requests from potential clients, assigns potential clients to slots, and detects when a connected client disconnects or times out.

Outside the scope of this standard, dedicated servers should keep the web backend informed of their status (ready to accept new clients, full, stopped), how many client slots are free to join, and any additional information required for the web backend to make informed decisions about which servers to send clients to via connect tokens.

## Server-Side Connection Process

The first thing the server must do is negotiate connection with potential clients.

When doing this it follows one rule: _clients must have a valid connect token to be able to connect!_

...

## Replay Protection

...
