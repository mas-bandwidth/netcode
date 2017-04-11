package netcode

import (
	"errors"
	"log"
	"strings"
	"time"
)

// ip types used in serialization of server addresses
const (
	ADDRESS_NONE = iota
	ADDRESS_IPV4
	ADDRESS_IPV6
)

// number of bytes for connect tokens
const CONNECT_TOKEN_BYTES = 2048

// Token used for connecting
type ConnectToken struct {
	sharedTokenData                      // a shared container holding the server addresses, client and server keys
	VersionInfo     []byte               // the version information for client <-> server communications
	ProtocolId      uint64               // protocol id for communications
	CreateTimestamp uint64               // when this token was created
	ExpireTimestamp uint64               // when this token expires
	Sequence        uint64               // the sequence id
	PrivateData     *ConnectTokenPrivate // reference to the private parts of this connect token
	TimeoutSeconds  uint32               // timeout of connect token in seconds
}

// Create a new empty token and empty private token
func NewConnectToken() *ConnectToken {
	token := &ConnectToken{}
	token.PrivateData = NewConnectTokenPrivate()
	return token
}

// Generates the token and private token data with the supplied config values and sequence id.
// This will also write and encrypt the private token
func (token *ConnectToken) Generate(config *Config, sequence uint64) error {
	token.CreateTimestamp = uint64(time.Now().Unix())
	token.ExpireTimestamp = token.CreateTimestamp + config.TokenExpiry
	token.VersionInfo = []byte(VERSION_INFO)
	token.ProtocolId = config.ProtocolId
	token.TimeoutSeconds = config.TimeoutSeconds
	token.Sequence = sequence

	userData, err := RandomBytes(USER_DATA_BYTES)
	if err != nil {
		return err
	}

	if err = token.PrivateData.Generate(config, userData); err != nil {
		return err
	}

	// copy directly from the private token since we don't want to generate 2 different keys
	token.ClientKey = token.PrivateData.ClientKey
	token.ServerKey = token.PrivateData.ServerKey
	token.ServerAddrs = token.PrivateData.ServerAddrs

	if _, err = token.PrivateData.Write(); err != nil {
		return err
	}

	if err = token.PrivateData.Encrypt(token.ProtocolId, token.ExpireTimestamp, sequence, config.PrivateKey); err != nil {
		return err
	}

	return nil
}

// Writes the ConnectToken and previously encrypted ConnectTokenPrivate data to a byte slice
func (token *ConnectToken) Write() ([]byte, error) {
	buffer := NewBuffer(CONNECT_TOKEN_BYTES)
	buffer.WriteBytes(token.VersionInfo)
	buffer.WriteUint64(token.ProtocolId)
	buffer.WriteUint64(token.CreateTimestamp)
	buffer.WriteUint64(token.ExpireTimestamp)
	buffer.WriteUint64(token.Sequence)

	// assumes private token has already been encrypted
	buffer.WriteBytes(token.PrivateData.Buffer())

	if err := token.WriteShared(buffer); err != nil {
		return nil, err
	}

	buffer.WriteUint32(token.TimeoutSeconds)
	return buffer.Buf, nil
}

// Takes in a slice of decrypted connect token bytes and generates a new ConnectToken.
// Note that the ConnectTokenPrivate is still encrypted at this point.
func ReadConnectToken(tokenBuffer []byte) (*ConnectToken, error) {
	var err error
	var privateData []byte

	buffer := NewBufferFromBytes(tokenBuffer)
	token := NewConnectToken()

	if token.VersionInfo, err = buffer.GetBytes(VERSION_INFO_BYTES); err != nil {
		return nil, errors.New("read connect token data has bad version info " + err.Error())
	}

	if strings.Compare(VERSION_INFO, string(token.VersionInfo)) != 0 {
		return nil, errors.New("read connect token data has bad version info: " + string(token.VersionInfo))
	}

	if token.ProtocolId, err = buffer.GetUint64(); err != nil {
		return nil, errors.New("read connect token data has bad protocol id " + err.Error())
	}

	if token.CreateTimestamp, err = buffer.GetUint64(); err != nil {
		return nil, errors.New("read connect token data has bad create timestamp " + err.Error())
	}

	if token.ExpireTimestamp, err = buffer.GetUint64(); err != nil {
		return nil, errors.New("read connect token data has bad expire timestamp " + err.Error())
	}

	if token.CreateTimestamp > token.ExpireTimestamp {
		return nil, errors.New("expire timestamp is > create timestamp")
	}

	if token.Sequence, err = buffer.GetUint64(); err != nil {
		return nil, errors.New("read connect data has bad sequence " + err.Error())
	}
	log.Printf("sequence: %x\n", token.Sequence)

	if privateData, err = buffer.GetBytes(CONNECT_TOKEN_PRIVATE_BYTES); err != nil {
		return nil, errors.New("read connect data has bad private data " + err.Error())
	}

	// it is still encrypted at this point.
	token.PrivateData.TokenData = NewBufferFromBytes(privateData)

	// reads servers, client and server key
	if err = token.ReadShared(buffer); err != nil {
		return nil, err
	}

	if token.TimeoutSeconds, err = buffer.GetUint32(); err != nil {
		return nil, err
	}

	return token, nil
}
