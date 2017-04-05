package netcode

import (
	"net"
	"errors"
	"strconv"
	"log"
	"go/token"
)

const (
	ADDRESS_NONE = iota
	ADDRESS_IPV4
	ADDRESS_IPV6
)

const CONNECT_TOKEN_BYTES = 2048

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

func (token *ConnectToken) Write() ([]byte, error) {
	buffer := NewBuffer(CONNECT_TOKEN_BYTES)
	buffer.WriteBytes([]byte(VERSION_INFO))
	buffer.WriteUint64(token.ProtocolId)
	buffer.WriteUint64(token.CreateTimestamp)
	buffer.WriteUint64(token.ExpireTimestamp)
	buffer.WriteUint64(token.Sequence)

	privateData, err := token.PrivateData.Write()
	if err != nil {
		return nil, err
	}
	buffer.WriteBytes(privateData)

	if err := writeServerData(buffer, token.PrivateData.ServerAddrs, token.PrivateData.ClientKey, token.PrivateData.ServerKey, token.PrivateData.UserData); err != nil {
		return nil, err
	}
	return buffer.Buf, nil
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

func writeServerData(buffer *Buffer, serverAddrs []net.UDPAddr, clientKey, serverKey, userData []byte) error {
	buffer.WriteUint32(uint32(len(serverAddrs)))

	for _, addr := range serverAddrs {
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

		for i := 0; i < len(parsed); i +=1 {
			buffer.WriteUint8(parsed[i])
		}

		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return err
		}
		buffer.WriteUint16(uint16(p))
	}
	buffer.WriteBytesN(clientKey, KEY_BYTES)
	buffer.WriteBytesN(serverKey, KEY_BYTES)
	buffer.WriteBytesN(userData, USER_DATA_BYTES)
	return nil
}