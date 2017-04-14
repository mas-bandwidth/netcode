[![Travis Build Status](https://travis-ci.org/networkprotocol/netcode.io.svg?branch=master)](https://travis-ci.org/networkprotocol/netcode.io)
[![](http://meritbadge.herokuapp.com/netcode)](https://crates.io/crates/netcode)
[![](https://docs.rs/netcode/badge.svg)](https://docs.rs/netcode)

# netcode.io

**netcode.io** is a simple protocol for creating secure client/server connections over UDP.

It’s designed for games like [agar.io](http://agar.io) that shunt players from a main website or web backend to a number of dedicated server instances, with each dedicated server having some maximum number of players.

It has the following features:

1. Connection oriented
2. Encrypts and sign packets
3. All packets are delivered over UDP
4. Only authenticated clients can connect to dedicated servers

# What are the benefits?

## Simplicity

netcode.io is a simple protocol that can easily be incorporated into a client, dedicated server or web backend.

It has no external dependencies except [libsodium](http://www.libsodium.org), which is widely used and well tested.

## Full bidirectional transfer of data

Once a netcode.io connection is established, data can be exchanged between client and server at any rate, bidirectionally.

## No head of line blocking

Data is sent across UDP so it's not subject to head of line blocking. No head of line blocking means games play better, as time series data like player inputs and object positions are transmitted as quickly as possible, without being artificially delayed waiting for dropped packets to be resent.

## Connection rate limiting can be performed on the web backend

Because netcode.io servers only accept connections from clients with short-lived connect tokens, traditional web rate limiting can be applied to the REST calls that generate connect tokens for authenticated users, instead of rate limiting incoming connections at the UDP protocol level.

# How does it work?

Please refer to the second half of this whitepaper: [Why can't I send UDP packets from a browser?](http://new.gafferongames.com/post/why_cant_i_send_udp_packets_from_a_browser/) 

For a complete technical specification, read the [netcode 1.0 standard](https://github.com/networkprotocol/netcode.io/blob/master/STANDARD.md).

# How can I help?

This is an open source project and we welcome contributions. Please join us!

Here are some things that we think would be helpful:

* Provide feedback on the reference implementation
* Study the code, and look for flaws and weaknesses
* Implement additional tests. Find ways to break the code!
* Create bindings for netcode.io for your favorite language
* Port netcode.io to your favorite language (eg. C#, Rust, Golang, Java, LUA).
* We welcome anybody who would like to volunteer to perform a security audit of the code
* Develop a testing framework to guarantee that different languages implementations conform to the [standard](https://github.com/networkprotocol/netcode.io/blob/master/STANDARD.md)

Please let me know if you have any more ideas, and feel free to ask questions and get involved by logging issues.

# Author

The author of this library is [Glenn Fiedler](https://www.linkedin.com/in/glennfiedler), a recognized expert in the field of game network programming with over 15 years experience in the game industry.

Glenn is currently writing an article series about the development of this library called [Building a Game Network Protocol](http://gafferongames.com/2016/05/10/building-a-game-network-protocol/).

You can support Glenn's work writing articles and open source code via [Patreon](http://www.patreon.com/gafferongames).

# Sponsors

**netcode.io** is generously sponsored by:

* **Gold Sponsors**
    * [Cloud Imperium Games](https://cloudimperiumgames.com)
    
* **Silver Sponsors**
    * [The Network Protocol Company](http://www.thenetworkprotocolcompany.com)
    
* **Bronze Sponsors**
    * [Kite & Lightning](http://kiteandlightning.la/)
    * [Data Realms](http://datarealms.com)
 
And by individual supporters on [Patreon](http://www.patreon.com/gafferongames). Thank you. You make this possible!

# License

[BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause).
