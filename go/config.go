package netcode

import "net"

type Config struct {
	ServerAddrs []net.UDPAddr
	TokenExpiry uint64
	ProtocolId uint64
	PrivateKey []byte
}

func NewConfig(serverAddrs []net.UDPAddr, expiry, protocolId uint64, privateKey []byte) *Config {
	c := &Config{}
	c.ServerAddrs = serverAddrs
	c.TokenExpiry = expiry
	c.ProtocolId = protocolId
	c.PrivateKey = privateKey
	return c
}
