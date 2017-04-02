package netcode

import (
	"net"
	"errors"
	"strconv"
	"time"
	"log"
)

const (
	ADDRESS_NONE = iota
	ADDRESS_IPV4
	ADDRESS_IPV6
)


// Token used for connecting
type ConnectToken struct {
	ClientId uint64 // client identifier
	ServerAddresses []net.UDPAddr // list of server addresses this client may connect to
	ClientKey []byte // client to server key
	ServerKey []byte // server to client key
	UserData []byte // user data
	ExpireTimestamp uint64
	TokenData *Buffer // connect token data
}

// create a new empty token
func NewConnectToken() *ConnectToken {
	token := &ConnectToken{}
	return token
}

// Generates the token with the supplied configuration values and clientId.
func (token *ConnectToken) Generate(config *Config, sequence, clientId uint64) error {
	var err error

	token.ClientId = clientId
	token.ServerAddresses = config.ServerAddrs

	if token.UserData, err = RandomBytes(USER_DATA_BYTES); err != nil {
		return err
	}

	if token.ClientKey, err = GenerateKey(); err != nil {
		return err
	}

	if token.ServerKey, err = GenerateKey(); err != nil {
		return err
	}

	if token.TokenData, err = WriteToken(token); err != nil {
		return err
	}

	creationTime := time.Now().Unix()
	token.ExpireTimestamp = uint64(creationTime) + config.TokenExpiry
	token.Encrypt(config.ProtocolId, sequence, config.PrivateKey)

	return nil
}

// Encrypts the token.TokenData
func (token *ConnectToken) Encrypt(protocolId, sequence uint64, privateKey []byte) error {
	additionalData, nonce := buildCryptData(protocolId, token.ExpireTimestamp, sequence)

	if err := EncryptAead(&token.TokenData.Buf, additionalData.Bytes(), nonce.Bytes(), privateKey); err != nil {
		return err
	}
	log.Printf("after encrypt: %#v\n", token.TokenData.Bytes())
	return nil
}

// Decrypts the tokendata and assigns it back to the backing buffer
func (token *ConnectToken) Decrypt(protocolId, sequence uint64, privateKey []byte) error {
	var err error

	additionalData, nonce := buildCryptData(protocolId, token.ExpireTimestamp, sequence)

	if token.TokenData.Buf, err = DecryptAead(token.TokenData.Bytes(), additionalData.Bytes(), nonce.Bytes(), privateKey); err != nil {
		return err
	}
	return nil
}

// builds the additional data and nonce necessary for encryption and decryption.
func buildCryptData(protocolId, expireTimestamp, sequence uint64) (*Buffer, *Buffer) {
	additionalData := NewBuffer(VERSION_INFO_BYTES+8+8)
	additionalData.WriteBytes([]byte(VERSION_INFO))
	additionalData.WriteUint64(protocolId)
	additionalData.WriteUint64(expireTimestamp)

	nonce := NewBuffer(SizeUint64)
	nonce.WriteUint64(sequence)

	return additionalData, nonce
}

// Writes the token data to the TokenData buffer and returns to caller
func WriteToken(token *ConnectToken) (*Buffer, error) {
	data := NewBuffer(CONNECT_TOKEN_PRIVATE_BYTES)
	data.WriteUint64(token.ClientId)
	data.WriteUint32(uint32(len(token.ServerAddresses)))

	for _, addr := range token.ServerAddresses {
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil, errors.New("invalid port for host: " + addr.String())
		}

		parsed := net.ParseIP(host)
		if parsed == nil {
			return nil, errors.New("invalid ip address")
		}

		if len(parsed) == 4 {
			data.WriteUint8(uint8(ADDRESS_IPV4))

		} else {
			data.WriteUint8(uint8(ADDRESS_IPV6))
		}

		for i := 0; i < len(parsed); i +=1 {
			data.WriteUint8(parsed[i])
		}

		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}
		data.WriteUint16(uint16(p))
	}
	data.WriteBytesN(token.ClientKey, KEY_BYTES)
	data.WriteBytesN(token.ServerKey, KEY_BYTES)
	data.WriteBytesN(token.UserData, USER_DATA_BYTES)
	return data, nil
}

// Takes in a slice of bytes and generates a new ConnectToken.
func ReadToken(tokenBuffer []byte) (*ConnectToken, error) {
	var err error
	var servers uint32
	var ipBytes []byte

	token := NewConnectToken()
	buffer := NewBufferFromBytes(tokenBuffer)

	if token.ClientId, err = buffer.GetUint64(); err != nil {
		return nil, err
	}

	servers, err = buffer.GetUint32()
	if err != nil {
		return nil, err
	}

	if servers <= 0 {
		return nil, errors.New("empty servers")
	}

	if servers > MAX_SERVERS_PER_CONNECT {
		return nil, errors.New("too many servers")
	}

	token.ServerAddresses = make([]net.UDPAddr, servers)

	for i := 0; i < int(servers); i+=1 {
		serverType, err := buffer.GetUint8()
		if err != nil {
			return nil, err
		}

		if serverType == ADDRESS_IPV4 {
			ipBytes, err = buffer.GetBytes(4)
		} else if serverType == ADDRESS_IPV6 {
			ipBytes, err = buffer.GetBytes(16)
		} else {
			return nil, errors.New("unknown ip address")
		}

		if err != nil {
			return nil, err
		}

		ip := net.IP(ipBytes)
		port, err := buffer.GetUint16()
		if err != nil {
			return nil, errors.New("invalid port")
		}
		token.ServerAddresses[i] = net.UDPAddr{IP: ip, Port: int(port)}
	}

	if token.ClientKey, err = buffer.GetBytes(KEY_BYTES); err != nil {
		return nil, errors.New("error reading client to server key")
	}

	if token.ServerKey, err = buffer.GetBytes(KEY_BYTES); err != nil {
		return nil, errors.New("error reading server to client key")
	}

	if token.UserData, err = buffer.GetBytes(USER_DATA_BYTES); err != nil {
		return nil, errors.New("error reading user data")
	}

	return token, nil
}