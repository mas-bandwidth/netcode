package netcode

import (
	"net"
	"errors"
	"strconv"
	"log"
)

const (
	ADDRESS_NONE = iota
	ADDRESS_IPV4
	ADDRESS_IPV6
)


// Token used for connecting
type ConnectToken struct {
	VersionInfo []byte
	ProtocolId uint64
	CreateTimestamp uint64
	ExpireTimestamp uint64
	Sequence uint64
	PrivateData *ConnectTokenPrivate
	TimeoutSeconds int
}

type ConnectTokenPrivate struct {
	ClientId uint64
	ServerAddrs []net.UDPAddr // list of server addresses this client may connect to
	ClientKey []byte // client to server key
	ServerKey []byte // server to client key
	UserData []byte // user data
	TokenData *Buffer // used to store the serialized buffer
}

// create a new empty token
func NewConnectToken() *ConnectToken {
	token := &ConnectToken{}
	return token
}

func (token *ConnectToken) ServerKey() []byte {
	return token.PrivateData.ServerKey
}

func (token *ConnectToken) ClientKey() []byte {
	return token.PrivateData.ClientKey
}

// list of server addresses this client may connect to
func (token *ConnectToken) ServerAddresses() []net.UDPAddr {
	return token.PrivateData.ServerAddrs
}

func (token *ConnectToken) ClientId() uint64 {
	return token.PrivateData.ClientId
}

// Generates the token with the supplied configuration values
func (token *ConnectToken) Generate(config *Config, clientId, currentTimestamp, sequence uint64) error {
	var err error

	privateData := &ConnectTokenPrivate{}
	token.PrivateData = privateData

	privateData.ClientId = clientId
	privateData.ServerAddrs = config.ServerAddrs

	if privateData.UserData, err = RandomBytes(USER_DATA_BYTES); err != nil {
		return err
	}

	if privateData.ClientKey, err = GenerateKey(); err != nil {
		return err
	}

	if privateData.ServerKey, err = GenerateKey(); err != nil {
		return err
	}

	if privateData.TokenData, err = WriteConnectToken(token); err != nil {
		return err
	}

	token.CreateTimestamp = currentTimestamp
	token.ExpireTimestamp = token.CreateTimestamp + config.TokenExpiry
	token.Encrypt(config.ProtocolId, sequence, config.PrivateKey)

	return nil
}

// Encrypts the token.TokenData
func (token *ConnectToken) Encrypt(protocolId, sequence uint64, privateKey []byte) error {
	additionalData, nonce := buildCryptData(protocolId, token.ExpireTimestamp, sequence)
	if err := EncryptAead(&token.PrivateData.TokenData.Buf, additionalData.Bytes(), nonce.Bytes(), privateKey); err != nil {
		return err
	}
	log.Printf("after encrypt: %#v\n", token.PrivateData.TokenData)
	return nil
}

// Decrypts the tokendata and assigns it back to the backing buffer
func (token *ConnectToken) Decrypt(protocolId, sequence uint64, privateKey []byte) error {
	var err error

	additionalData, nonce := buildCryptData(protocolId, token.ExpireTimestamp, sequence)
	if token.PrivateData.TokenData.Buf, err = DecryptAead(token.PrivateData.TokenData.Bytes(), additionalData.Bytes(), nonce.Bytes(), privateKey); err != nil {
		return err
	}
	return nil
}

// builds the additional data and nonce necessary for encryption and decryption.
func buildCryptData(protocolId, expireTimestamp, sequence uint64) (*Buffer, *Buffer) {
	additionalData := NewBuffer(VERSION_INFO_BYTES+8+8)
	additionalData.WriteBytes([]byte(VERSION_INFO))
	log.Printf("buildCryptData %x %x\n", protocolId, expireTimestamp)
	additionalData.WriteUint64(protocolId)
	additionalData.WriteUint64(expireTimestamp)

	nonce := NewBuffer(SizeUint64)
	nonce.WriteUint64(sequence)

	return additionalData, nonce
}

// Writes the token data to the TokenData buffer and returns to caller
func WriteConnectToken(token *ConnectToken) (*Buffer, error) {
	data := NewBuffer(CONNECT_TOKEN_PRIVATE_BYTES)
	data.WriteUint64(token.PrivateData.ClientId)
	data.WriteUint32(uint32(len(token.PrivateData.ServerAddrs)))

	for _, addr := range token.ServerAddresses() {
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
	data.WriteBytesN(token.PrivateData.ClientKey, KEY_BYTES)
	data.WriteBytesN(token.PrivateData.ServerKey, KEY_BYTES)
	data.WriteBytesN(token.PrivateData.UserData, USER_DATA_BYTES)
	return data, nil
}

// Takes in a slice of bytes and generates a new ConnectToken after decryption.
func ReadConnectToken(tokenBuffer []byte, protocolId, expireTimestamp, sequence uint64, privateKey []byte) (*ConnectToken, error) {
	var err error
	var servers uint32
	var ipBytes []byte

	token := NewConnectToken()
	token.PrivateData = &ConnectTokenPrivate{}
	token.ExpireTimestamp = expireTimestamp

	token.PrivateData.TokenData = NewBufferFromBytes(tokenBuffer)
	if err := token.Decrypt(protocolId, sequence, privateKey); err != nil {
		return nil, errors.New("error decrypting connection token: " + err.Error())
	}

	if token.PrivateData.ClientId, err = token.PrivateData.TokenData.GetUint64(); err != nil {
		return nil, err
	}

	log.Printf("clientid: %x\n", token.PrivateData.ClientId)

	servers, err = token.PrivateData.TokenData.GetUint32()
	if err != nil {
		return nil, err
	}

	if servers <= 0 {
		return nil, errors.New("empty servers")
	}

	if servers > MAX_SERVERS_PER_CONNECT {
		log.Printf("got %d expected %d\n", servers, MAX_SERVERS_PER_CONNECT)
		return nil, errors.New("too many servers")
	}

	token.PrivateData.ServerAddrs = make([]net.UDPAddr, servers)

	for i := 0; i < int(servers); i+=1 {
		serverType, err := token.PrivateData.TokenData.GetUint8()
		if err != nil {
			return nil, err
		}

		if serverType == ADDRESS_IPV4 {
			ipBytes, err = token.PrivateData.TokenData.GetBytes(4)
		} else if serverType == ADDRESS_IPV6 {
			ipBytes, err = token.PrivateData.TokenData.GetBytes(16)
		} else {
			return nil, errors.New("unknown ip address")
		}

		if err != nil {
			return nil, err
		}

		ip := net.IP(ipBytes)
		port, err := token.PrivateData.TokenData.GetUint16()
		if err != nil {
			return nil, errors.New("invalid port")
		}
		token.PrivateData.ServerAddrs[i] = net.UDPAddr{IP: ip, Port: int(port)}
	}

	if token.PrivateData.ClientKey, err = token.PrivateData.TokenData.GetBytes(KEY_BYTES); err != nil {
		return nil, errors.New("error reading client to server key")
	}

	if token.PrivateData.ServerKey, err = token.PrivateData.TokenData.GetBytes(KEY_BYTES); err != nil {
		return nil, errors.New("error reading server to client key")
	}

	if token.PrivateData.UserData, err = token.PrivateData.TokenData.GetBytes(USER_DATA_BYTES); err != nil {
		return nil, errors.New("error reading user data")
	}

	return token, nil
}