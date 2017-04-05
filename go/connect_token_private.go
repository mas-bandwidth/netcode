package netcode

import (
	"net"
	"errors"
	"strconv"
	"log"
)

type ConnectTokenPrivate struct {
	ClientId uint64
	ServerAddrs []net.UDPAddr // list of server addresses this client may connect to
	ClientKey []byte // client to server key
	ServerKey []byte // server to client key
	UserData []byte // used to store user data
	TokenData *Buffer // used to store the serialized buffer
}

func NewConnectTokenPrivate() *ConnectTokenPrivate {
	p := &ConnectTokenPrivate{}
	p.TokenData = NewBuffer(CONNECT_TOKEN_PRIVATE_BYTES)
	return p
}

// Reads the token properties from the internal TokenData buffer.
func (p *ConnectTokenPrivate) Read() error {
	var err error

	if p.ClientId, err = p.TokenData.GetUint64(); err != nil {
		return err
	}

	if err := p.readServerData(); err != nil {
		return err
	}

	if p.ClientKey, err = p.TokenData.GetBytes(KEY_BYTES); err != nil {
		return errors.New("error reading client to server key")
	}

	if p.ServerKey, err = p.TokenData.GetBytes(KEY_BYTES); err != nil {
		return errors.New("error reading server to client key")
	}

	if p.UserData, err = p.TokenData.GetBytes(USER_DATA_BYTES); err != nil {
		return errors.New("error reading user data")
	}

	return nil
}

func (p *ConnectTokenPrivate) readServerData() error {
	var err error
	var servers uint32
	var ipBytes []byte

	servers, err = p.TokenData.GetUint32()
	if err != nil {
		return err
	}

	if servers <= 0 {
		return errors.New("empty servers")
	}

	if servers > MAX_SERVERS_PER_CONNECT {
		log.Printf("got %d expected %d\n", servers, MAX_SERVERS_PER_CONNECT)
		return errors.New("too many servers")
	}

	p.ServerAddrs = make([]net.UDPAddr, servers)

	for i := 0; i < int(servers); i+=1 {
		serverType, err := p.TokenData.GetUint8()
		if err != nil {
			return err
		}

		if serverType == ADDRESS_IPV4 {
			ipBytes, err = p.TokenData.GetBytes(4)
		} else if serverType == ADDRESS_IPV6 {
			ipBytes, err = p.TokenData.GetBytes(16)
		} else {
			return errors.New("unknown ip address")
		}

		if err != nil {
			return err
		}

		ip := net.IP(ipBytes)
		port, err := p.TokenData.GetUint16()
		if err != nil {
			return errors.New("invalid port")
		}
		p.ServerAddrs[i] = net.UDPAddr{IP: ip, Port: int(port)}
	}
	return nil
}

// Writes the token data to a byte slice and returns to caller
func (token *ConnectTokenPrivate) Write() ([]byte, error) {
	data := NewBuffer(CONNECT_TOKEN_PRIVATE_BYTES)
	data.WriteUint64(token.ClientId)

	if err := writeServerData(data, token.ServerAddrs, token.ClientKey, token.ServerKey, token.UserData); err != nil {
		return nil, err
	}
	return data.Buf, nil
}