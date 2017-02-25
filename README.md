[![Travis Build Status](https://travis-ci.org/networkprotocol/netcode.io.svg?branch=master)](https://travis-ci.org/networkprotocol/netcode.io)

# netcode.io

**netcode.io** is a protocol for creating secure connections between clients and dedicated servers over UDP.

It’s designed for games like [agar.io](http://agar.io) that need to shunt players off from the main website to a number of dedicated server instances, each with some maximum number of players (up to 256 players per-instance in the reference implementation). 

It has the following properties:

1. It's connection oriented
2. It encrypts and sign packets
3. It provides authentication support so only authenticated clients can connect to dedicated servers

This github repository contains the reference implementation of this protocol in C.

# What are the benefits?

## Full bidirectional transfer of data

Once a netcode.io connection is established, data can be exchanged between client and server at any rate, bidirectionally.

There is no request/response pattern like HTTP.

## No head of line blocking

All data is transmitted over UDP. Unlike data sent over WebSockets, data sent across netcode.io is not subject to head of line blocking.

No head of line blocking means games play better, as time critical data like player inputs and the state of the world are transmitted as quickly as possible, without being artificially delayed while waiting for dropped packets to be resent.

## Simplicity

netcode.io is a simple protocol that can easily be incorporated into a client, dedicated server or web backend.

It has no external dependencies except [libsodium](http://www.libsodium.org), which is widely used and well tested.

# How does it work?

Please refer to this whitepaper [Why can't I send UDP packets from a browser?](http://173.255.195.190/gafferongames/post/why_cant_i_send_udp_packets_from_a_browser/)

# How can I help?

This is an open source project. Please help if you can:

* Provide feedback on the reference implementation
* Study the code, and look for flaws and weaknesses
* Implement additional tests. Find ways to break the code!
* We welcome anybody who would like to volunteer to perform a security audit of the code
* Port netcode.io to your favorite language (eg. C#, Rust, Golang).
* Create bindings for netcode.io for your favorite language
* Help me finish writing the spec and provide feedback on the spec!
* Develop a testing framework to guarantee that different languages implementations confirm to the spec.

Please let me know if you have any more ideas, and feel free to ask questions and get involved by logging issues.

# Author

The author of this library is [Glenn Fiedler](https://www.linkedin.com/in/glennfiedler), a recognized expert in the field of game network programming with over 15 years experience in the game industry.

Glenn is currently writing an article series about the development of this library called [Building a Game Network Protocol](http://gafferongames.com/2016/05/10/building-a-game-network-protocol/).

You can support Glenn's work writing articles and open source code via [Patreon](http://www.patreon.com/gafferongames).

# Sponsors

**netcode.io** is generously sponsored by:

* Gold Sponsors
 - [Cloud Imperium Games](https://cloudimperiumgames.com)
 
* Silver Sponsors
 - [The Network Protocol Company](http://www.thenetworkprotocolcompany.com)

* Bronze Sponsors
 - [Kite & Lightning](http://kiteandlightning.la/)
 - [Data Realms](http://datarealms.com)
 
And by individual supporters on [Patreon](http://www.patreon.com/gafferongames). Thank you. You make this possible!

# License

[BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause).
