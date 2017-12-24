[![Travis Build Status](https://travis-ci.org/networkprotocol/netcode.io.svg?branch=master)](https://travis-ci.org/networkprotocol/netcode.io)

# netcode.io

**netcode.io** is a simple protocol for creating secure client/server connections over UDP.

It’s designed for games that shunt players from a main website or web backend to a number of dedicated server instances, with each dedicated server having some maximum number of players.

It has the following features:

1. Connection oriented
2. Encrypts and sign packets
3. All packets are delivered over UDP
4. Only authenticated clients can connect to dedicated servers

# Source Code

This repository holds the reference implementation of netcode.io in C.

Other netcode.io repositories include:

* [netcode.io C# implementation](https://github.com/KillaMaaki/Netcode.IO.NET)
* [netcode.io Golang implementation](https://github.com/wirepair/netcode)
* [netcode.io Rust implementation](https://github.com/vvanders/netcode.io)
* [netcode.io for Unity](https://github.com/KillaMaaki/Unity-Netcode.IO)
* [netcode.io for UE4](https://github.com/RedpointGames/netcode.io-UE4)
* [netcode.io browser plugin](https://github.com/RedpointGames/netcode.io-browser)

# How does it work?

Please refer to the second half of this whitepaper: [Why can't I send UDP packets from a browser?](http://gafferongames.com/post/why_cant_i_send_udp_packets_from_a_browser/) 

For a complete technical specification, read the [netcode 1.01 standard](https://github.com/networkprotocol/netcode.io/blob/master/STANDARD.md).

# How can I help?

This is an open source project and we welcome contributions. Please join us!

Here are some things that we think would be helpful:

* Provide feedback on the reference implementation
* Study the code, and look for flaws and weaknesses
* Port netcode.io to your favorite language (eg. Java, Lua, Python, Ruby...)
* We welcome anybody who would like to volunteer to perform a security audit of the code
* Develop a testing framework to guarantee that different languages implementations conform to the [standard](https://github.com/networkprotocol/netcode.io/blob/master/STANDARD.md)

Please let me know if you have any more ideas, and feel free to ask questions and get involved by logging issues.

# Contributors

These people are awesome:

* [Val Vanders](https://github.com/vvanders) - Rust Implementation
* [Isaac Dawson](https://github.com/wirepair) - Golang Implementation
* [June Rhodes](https://github.com/hach-que) - C# bindings, browser support, UE4 integration.
* [Alan Stagner](https://github.com/KillaMaaki) - Unity integration, C# implementation.

Thanks for your contributions to netcode.io!

# Author

The author of this library is [Glenn Fiedler](https://www.linkedin.com/in/glennfiedler), a recognized expert in the field of game network programming with over 15 years experience in the game industry.

Glenn wrote an article series about the development of this library called [Building a Game Network Protocol](http://gafferongames.com/2016/05/10/building-a-game-network-protocol/).

Open source libraries by the same author include: [yojimbo](http://libyojimbo.com) and [reliable.io](https://github.com/networkprotocol/reliable.io)

# Sponsors

**netcode.io** is generously sponsored by:

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
