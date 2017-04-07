package netcode

import (
	"errors"
	"net"
	"strconv"
)

// This struct contains data that is shared in both public and private parts of the
// connect token.
type sharedTokenData struct {
	ServerAddrs []net.UDPAddr // list of server addresses this client may connect to
	ClientKey   []byte        // client to server key
	ServerKey   []byte        // server to client key
}

// Reads and validates the servers, client <-> server keys.
func (shared *sharedTokenData) ReadShared(buffer *Buffer) error {
	var err error
	var servers uint32
	var ipBytes []byte

	servers, err = buffer.GetUint32()
	if err != nil {
		return err
	}

	if servers <= 0 {
		return errors.New("empty servers")
	}

	if servers > MAX_SERVERS_PER_CONNECT {
		return errors.New("too many servers")
	}

	shared.ServerAddrs = make([]net.UDPAddr, servers)

	for i := 0; i < int(servers); i += 1 {
		serverType, err := buffer.GetUint8()
		if err != nil {
			return err
		}

		if serverType == ADDRESS_IPV4 {
			ipBytes, err = buffer.GetBytes(4)
		} else if serverType == ADDRESS_IPV6 {
			ipBytes, err = buffer.GetBytes(16)
		} else {
			return errors.New("unknown ip address")
		}

		if err != nil {
			return err
		}

		ip := net.IP(ipBytes)
		port, err := buffer.GetUint16()
		if err != nil {
			return errors.New("invalid port")
		}
		shared.ServerAddrs[i] = net.UDPAddr{IP: ip, Port: int(port)}
	}

	if shared.ClientKey, err = buffer.GetBytes(KEY_BYTES); err != nil {
		return err
	}

	if shared.ServerKey, err = buffer.GetBytes(KEY_BYTES); err != nil {
		return err
	}

	return nil
}

// Writes the servers and client <-> server keys to the supplied buffer
func (shared *sharedTokenData) WriteShared(buffer *Buffer) error {
	buffer.WriteUint32(uint32(len(shared.ServerAddrs)))

	for _, addr := range shared.ServerAddrs {
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return errors.New("invalid port for host: " + addr.String())
		}

		parsed := net.ParseIP(host)
		if parsed == nil {
			return errors.New("invalid ip address")
		}

		if len(parsed) == 4 {
			buffer.WriteUint8(uint8(ADDRESS_IPV4))

		} else {
			buffer.WriteUint8(uint8(ADDRESS_IPV6))
		}

		for i := 0; i < len(parsed); i += 1 {
			buffer.WriteUint8(parsed[i])
		}

		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return err
		}
		buffer.WriteUint16(uint16(p))
	}
	buffer.WriteBytesN(shared.ClientKey, KEY_BYTES)
	buffer.WriteBytesN(shared.ServerKey, KEY_BYTES)
	return nil
}

// Generates the shared data, should only really be called by ConnectTokenPrivate
// since the same data will be copied/referenced by ConnectToken
func (shared *sharedTokenData) GenerateShared(config *Config) error {
	var err error

	shared.ServerAddrs = config.ServerAddrs
	if shared.ClientKey, err = GenerateKey(); err != nil {
		return err
	}

	if shared.ServerKey, err = GenerateKey(); err != nil {
		return err
	}
	return nil
}
