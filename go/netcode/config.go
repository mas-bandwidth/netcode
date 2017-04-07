package netcode

import "net"

// A configuration container for various properties that are passed to packets
type Config struct {
	ClientId       uint64        // client id used in packet generation
	ServerAddrs    []net.UDPAddr // list of server addresses
	TokenExpiry    uint64        // when the token expires, current time + this value.
	TimeoutSeconds uint32        // timeout in seconds for connect token
	ProtocolId     uint64        // the protocol id used between server <-> client
	PrivateKey     []byte        // the private key used for encryption
}

// Creates a new config holder for ease of passing around to packet generation and client/servers
func NewConfig(serverAddrs []net.UDPAddr, timeoutSeconds uint32, expiry, clientId, protocolId uint64, privateKey []byte) *Config {
	c := &Config{}
	c.ClientId = clientId
	c.ServerAddrs = serverAddrs
	c.TokenExpiry = expiry
	c.ProtocolId = protocolId
	c.PrivateKey = privateKey
	c.TimeoutSeconds = timeoutSeconds
	return c
}
