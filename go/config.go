package netcode

import "net"

type Config struct {
	ClientId       uint64
	ServerAddrs    []net.UDPAddr
	TokenExpiry    uint64
	TimeoutSeconds uint32
	ProtocolId     uint64
	PrivateKey     []byte
}

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
