# netcode.io standard

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
