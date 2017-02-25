[![Travis Build Status](https://travis-ci.org/networkprotocol/netcode.io.svg?branch=master)](https://travis-ci.org/networkprotocol/netcode.io)

# netcode.io

**netcode.io** is a simple network protocol that lets clients securely connect to dedicated servers and communicate over UDP. It’s connection oriented and encrypts and signs packets, and provides authentication support so only authenticated clients can connect to dedicated servers.

It’s designed for games like [agar.io](http://agar.io) that need to shunt players off from the main website to a number of dedicated server instances, each with some maximum number of players (up to 256 players per-instance in the reference implementation).

The basic idea is that the web backend performs authentication and when a client wants to play, it makes a REST call to obtain a connect token which is passed to the dedicated server as part of the connection handshake over UDP.

Connect tokens are short lived and rely on a shared private key between the web backend and the dedicated server instances. The benefit of this approach is that only authenticated clients are able to connect to the dedicated servers.

Over the past month I’ve created a reference implementation of netcode.io in C. It’s licenced under the BSD 3-Clause open source licence. 

Over the next few months, I hope to continue refining this implementation, spend time writing a spec, and work with people to port netcode.io to different languages.

Your feedback on the reference implementation is appreciated.

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
