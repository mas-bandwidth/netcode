[![Travis Build Status](https://travis-ci.org/networkprotocol/netcode.io.svg?branch=master)](https://travis-ci.org/networkprotocol/netcode.io)

# netcode.io

**netcode.io** is a connection-oriented protocol built on top of UDP. 

It's designed for client/server games with dedicated servers, like modern first person shooters.

It has the following features:

* Only authenticated clients can connect to your server.
* Packet encryption and signature checks.
* Protection against man-in-the-middle attacks.
* Protection against DDoS amplification attacks.
* Protection against packet replay attacks.
* Protection against zombie clients.

netcode.io is stable and well tested having been used in AAA game projects for over 2 years now.

# How does it work?

Please refer to the second half of this whitepaper: [Why can't I send UDP packets from a browser?](http://gafferongames.com/post/why_cant_i_send_udp_packets_from_a_browser/) 

For a complete technical specification, read the [netcode 1.02 standard](https://github.com/networkprotocol/netcode.io/blob/master/STANDARD.md).

# Source Code

This repository holds the implementation of netcode.io in C.

Other netcode.io repositories include:

* [netcode.io C# implementation](https://github.com/KillaMaaki/Netcode.IO.NET)
* [netcode.io Golang implementation](https://github.com/wirepair/netcode)
* [netcode.io Rust implementation](https://github.com/jaynus/netcode.io) (updated fork of [vvanders/netcode.io](https://github.com/vvanders/netcode.io))
* [netcode.io for Unity](https://github.com/KillaMaaki/Unity-Netcode.IO)
* [netcode.io for UE4](https://github.com/RedpointGames/netcode.io-UE4)
* [netcode.io browser plugin](https://github.com/RedpointGames/netcode.io-browser)

# Contributors

These people are awesome:

* [Val Vanders](https://github.com/vvanders) - Rust Implementation
* [Walter Pearce](https://github.com/jaynus) - Rust Implementation
* [Isaac Dawson](https://github.com/wirepair) - Golang Implementation
* [June Rhodes](https://github.com/hach-que) - C# bindings, browser support, UE4 integration
* [Alan Stagner](https://github.com/KillaMaaki) - Unity integration, C# implementation
* [Jérôme Leclercq](https://github.com/DrLynix) - Support for random connect token nonce
* [Randy Gaul](https://github.com/RandyGaul) - Discovered vulnerability in replay protection

Thanks for your contributions to netcode.io!

# Author

The author of this library is [Glenn Fiedler](https://www.linkedin.com/in/glennfiedler).

Glenn wrote an article series about the development of this library called [Building a Game Network Protocol](https://gafferongames.com/categories/building-a-game-network-protocol).

Other open source libraries by the same author include: [yojimbo](http://libyojimbo.com) and [reliable.io](https://github.com/networkprotocol/reliable.io)

# Sponsors

**netcode.io** was generously sponsored by:

* **Gold Sponsors**
    * [Remedy Entertainment](http://www.remedygames.com/)
    * [Cloud Imperium Games](https://cloudimperiumgames.com)
    
* **Silver Sponsors**
    * [Moon Studios](http://www.oriblindforest.com/#!moon-3/)
    * [The Network Protocol Company](http://www.thenetworkprotocolcompany.com)
    
* **Bronze Sponsors**
    * [Kite & Lightning](http://kiteandlightning.la/)
    * [Data Realms](http://datarealms.com)
 
And by individual supporters on Patreon. Thank you. You made this possible!

# License

[BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause).
