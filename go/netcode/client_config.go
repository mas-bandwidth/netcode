package netcode

import "net"

// A configuration container for various properties of a client
type ClientConfig struct {
	ClientId       uint64        // client id used in packet generation
	ServerAddrs    []net.UDPAddr // list of server addresses
	TokenExpiry    uint64        // when the token expires, current time + this value.
	TimeoutSeconds uint32        // timeout in seconds for connect token
	ProtocolId     uint64        // the protocol id used between server <-> client
	ClientKey      []byte        // the client -> server key used for encryption
	ServerKey      []byte        // the server -> client key used for encryption
}

// Creates a new config holder for ease of passing around to packet generation and client/servers
func NewClientConfig(serverAddrs []net.UDPAddr, timeoutSeconds uint32, expiry, clientId, protocolId uint64, clientKey, serverKey []byte) *ClientConfig {
	c := &ClientConfig{}
	c.ClientId = clientId
	c.ServerAddrs = serverAddrs
	c.TokenExpiry = expiry
	c.ProtocolId = protocolId
	c.ClientKey = clientKey
	c.ServerKey = serverKey
	c.TimeoutSeconds = timeoutSeconds
	return c
}
