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

	token.CreateTimestamp = currentTimestamp
	token.ExpireTimestamp = token.CreateTimestamp + config.TokenExpiry
	return nil
}

// Writes the token data to a byte slice and returns to caller
func (token *ConnectToken) Write() ([]byte, error) {
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
	return data.Buf, nil
}

// Takes in a slice of bytes and generates a new ConnectToken after decryption.
func ReadConnectToken(tokenBuffer []byte, protocolId, expireTimestamp, sequence uint64, privateKey []byte) (*ConnectToken, error) {
	var err error
	var privateData []byte

	token := NewConnectToken()
	token.ExpireTimestamp = expireTimestamp

	if privateData, err = DecryptConnectTokenPrivate(tokenBuffer, protocolId, expireTimestamp, sequence, privateKey); err != nil {
		return nil, errors.New("error decrypting connection token: " + err.Error())
	}

	private := NewConnectTokenPrivate()
	private.TokenData = NewBufferFromBytes(privateData)
	if err = private.Read(); err != nil {
		return nil, err
	}
	token.PrivateData = private
	return token, nil
}

// Encrypts the supplied buffer for the token private parts
func EncryptConnectTokenPrivate(privateData *[]byte, protocolId, expireTimestamp, sequence uint64, privateKey []byte) error {
	additionalData, nonce := buildCryptData(protocolId, expireTimestamp, sequence)

	if err := EncryptAead(privateData, additionalData, nonce, privateKey); err != nil {
		return err
	}
	return nil
}

// Decrypts the supplied privateData buffer and generates a new ConnectTokenPrivate instance
func DecryptConnectTokenPrivate(privateData []byte, protocolId, expireTimestamp, sequence uint64, privateKey []byte) ([]byte, error) {
	additionalData, nonce := buildCryptData(protocolId, expireTimestamp, sequence)
	return DecryptAead(privateData, additionalData, nonce, privateKey)
}

// builds the additional data and nonce necessary for encryption and decryption.
func buildCryptData(protocolId, expireTimestamp, sequence uint64) ([]byte, []byte) {
	additionalData := NewBuffer(VERSION_INFO_BYTES+8+8)
	additionalData.WriteBytes([]byte(VERSION_INFO))
	additionalData.WriteUint64(protocolId)
	additionalData.WriteUint64(expireTimestamp)

	nonce := NewBuffer(SizeUint64)
	nonce.WriteUint64(sequence)

	return additionalData.Buf, nonce.Buf
}