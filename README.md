[![Travis Build Status](https://travis-ci.org/networkprotocol/netcode.io.svg?branch=master)](https://travis-ci.org/networkprotocol/netcode.io)

# netcode.io

**netcode.io** is a network protocol for secure client/server connections to dedicated servers over UDP.

It’s designed for games like [agar.io](http://agar.io) that need to shunt players off from the main website to a number of dedicated server instances, each with some maximum number of players (up to 256 players per-instance in the reference implementation). 

The protocol is:

1. It's connection oriented
2. It encrypts and sign packets
3. It provides authentication support so only authenticated clients can connect to dedicated servers

And of course, because the data is transmitted over UDP, not TCP, data sent across netcode.io is not subject to head of line blocking.

This means that your time series data like player inputs, and player positions arrive as rapidly as possible.

## How does it work?

To implement this, the authenticated performed by the web backend is transferred to dedicated servers across UDP using a short lived _connect token_. This token is passed across UDP as part of the connection handshake, and ensures that any rate limiting for connections can be done at a per-authenticated user basis, rather than a having to write rules across each dedicated server instance running your game.


the basic idea is that the web backend performs authentication and when a client wants to play, the client makes a REST call to obtain a connect token. Connect tokens are short lived and rely on a shared private key between the web backend and the dedicated server instances. The benefit of this approach is that only clients with a valid connect token are able to connect to the dedicated servers.

For more information, please read [Why can't I send UDP packets from a browser?](http://173.255.195.190/gafferongames/post/why_cant_i_send_udp_packets_from_a_browser/)

## How can I help?

This is an open source project. I need your help!

What can you do that is useful:

* Study the code, and look for flaws and weaknesses
* Implement additional tests. Find ways to break the code
* If you are a security professional, please contact me if you would like to help with the security audit.
* Port netcode.io to your favorite languge.
* Help me write the netcode
* Help create a test suite and framework to validate new implementations are conform to the spec

This github repository contains the reference implementation of netcode.io. I'm happy to answer any questions you have, just log an issue, and if you are interested in helping port netcode.io to other languages like C#

## Author

The author of this library is [Glenn Fiedler](https://www.linkedin.com/in/glennfiedler), a recognized expert in the field of game network programming with over 15 years experience in the game industry.

Glenn is currently writing an article series about the development of this library called [Building a Game Network Protocol](http://gafferongames.com/2016/05/10/building-a-game-network-protocol/).

You can support Glenn's work writing articles and open source code via [Patreon](http://www.patreon.com/gafferongames).

## Sponsors

**netcode.io** is generously sponsored by:

* Gold Sponsors
 - [Cloud Imperium Games](https://cloudimperiumgames.com)
 
* Silver Sponsors
 - [The Network Protocol Company](http://www.thenetworkprotocolcompany.com)

* Bronze Sponsors
 - [Kite & Lightning](http://kiteandlightning.la/)
 - [Data Realms](http://datarealms.com)
 
And by individual supporters on [Patreon](http://www.patreon.com/gafferongames). Thank you. You make this possible!

## License

[BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause).
