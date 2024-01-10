[![Build status](https://github.com/networkprotocol/netcode/workflows/CI/badge.svg)](https://github.com/networkprotocol/netcode/actions?query=workflow%3ACI)

# netcode

**netcode** is a secure connection-based client/server protocol built on top of UDP.

![image](https://github.com/mas-bandwidth/netcode/assets/696656/034909bd-95c5-460a-8516-f24fca4410a1)

It has the following features:

* Secure client connection with connect tokens
* Client slot system where each client is assigned a client index on connect
* Encrypted and signed packets

and protects your game server from:

* Zombie clients
* Packet sniffing
* Man in the middle
* DDoS amplification
* Packet replay attacks

netcode is stable and production ready.

# Usage

Start by generating a random 32 byte private key. Do not share your private key with _anybody_. 

Especially, **do not include your private key in your client executable!**

Here is a test private key:

```c
static uint8_t private_key[NETCODE_KEY_BYTES] = { 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 
                                                  0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4, 
                                                  0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                                  0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };
```

Create a server with the private key:

```c
char * server_address = "127.0.0.1:40000";

struct netcode_server_config_t server_config;
netcode_default_server_config( &server_config );
memcpy( &server_config.private_key, private_key, NETCODE_KEY_BYTES );

struct netcode_server_t * server = netcode_server_create( server_address, &server_config, time );
if ( !server )
{
    printf( "error: failed to create server\n" );
    return 1;
}
```

Then start the server with the number of client slots you want:

```c
netcode_server_start( server, 16 );
```

To connect a client, your client should hit a REST API to your backend that returns a _connect token_.

Using a connect token secures your server so that only clients authorized with your backend can connect.

```c
netcode_client_connect( client, connect_token );
```

Once the client connects to the server, the client is assigned a client index and can exchange encrypted and signed packets with the server.

For more details please see [client.c](client.c) and [server.c](server.c)

# Source Code

This repository holds the implementation of netcode in C.

Other netcode implementations include:

* [netcode C# implementation](https://github.com/KillaMaaki/Netcode.IO.NET)
* [netcode Golang implementation](https://github.com/wirepair/netcode)
* [netcode Rust implementation](https://github.com/jaynus/netcode.io) (updated fork of [vvanders/netcode.io](https://github.com/vvanders/netcode.io))
* [netcode Rust implemetation](https://github.com/benny-n/netcode) (new from scratch Rust implementation)
* [netcode for Unity](https://github.com/KillaMaaki/Unity-Netcode.IO)
* [netcode for UE4](https://github.com/RedpointGames/netcode.io-UE4)
* [netcode for Typescript](https://github.com/bennychen/netcode.io-typescript)

If you'd like to create your own implementation of netcode, please read the [netcode 1.02 standard](STANDARD.md).

# Contributors

These people are awesome:

* [Val Vanders](https://github.com/vvanders) - Rust Implementation
* [Walter Pearce](https://github.com/jaynus) - Rust Implementation
* [Isaac Dawson](https://github.com/wirepair) - Golang Implementation
* [Alan Stagner](https://github.com/KillaMaaki) - Unity integration, C# implementation
* [Jérôme Leclercq](https://github.com/SirLynix) - Support for random connect token nonce
* [Randy Gaul](https://github.com/RandyGaul) - Discovered vulnerability in replay protection
* [Benny Chen](https://github.com/bennychen) - Typescript Implementation
* [Benny Nazimov](https://github.com/benny-n) - Rust implementation

Thanks for your contributions to netcode!

# Author

The author of this library is Glenn Fiedler.

Other open source libraries by the same author include: [reliable](https://github.com/mas-bandwidth/reliable), [serialize](https://github.com/mas-bandwidth/serialize), and [yojimbo](https://github.com/mas-bandwidth/yojimbo).

If you find this software useful, [please consider sponsoring it](https://github.com/sponsors/mas-bandwidth). Thanks!

# License

[BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause).

