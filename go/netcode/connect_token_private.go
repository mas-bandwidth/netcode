package netcode

import (
	"errors"
)

// The private parts of a connect token
type ConnectTokenPrivate struct {
	sharedTokenData         // holds the server addresses, client <-> server keys
	ClientId        uint64  // id for this token
	UserData        []byte  // used to store user data
	TokenData       *Buffer // used to store the serialized/encrypted buffer
}

// Create a new connect token private with an empty TokenData buffer
func NewConnectTokenPrivate() *ConnectTokenPrivate {
	p := &ConnectTokenPrivate{}
	p.TokenData = NewBuffer(CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES)
	return p
}

// Create a new connect token private with an pre-set, encrypted buffer
// Caller is expected to call Decrypt() and Read() to set the instances properties
func NewConnectTokenPrivateEncrypted(buffer []byte) *ConnectTokenPrivate {
	p := &ConnectTokenPrivate{}
	p.TokenData = NewBufferFromBytes(buffer)
	return p
}

// Helper to return the internal []byte of the private data
func (p *ConnectTokenPrivate) Buffer() []byte {
	return p.TokenData.Buf
}

// Reads the configuration values to set various properties of this private token data
// and requires a supplied userData slice.
func (p *ConnectTokenPrivate) Generate(config *Config, userData []byte) error {
	p.ClientId = config.ClientId
	p.UserData = userData
	return p.GenerateShared(config)
}

// Reads the token properties from the internal TokenData buffer.
func (p *ConnectTokenPrivate) Read() error {
	var err error

	if p.ClientId, err = p.TokenData.GetUint64(); err != nil {
		return err
	}

	if err = p.ReadShared(p.TokenData); err != nil {
		return err
	}

	if p.UserData, err = p.TokenData.GetBytes(USER_DATA_BYTES); err != nil {
		return errors.New("error reading user data")
	}

	return nil
}

// Writes the token data to our TokenData buffer and alternatively returns the buffer to caller.
func (p *ConnectTokenPrivate) Write() ([]byte, error) {
	p.TokenData.WriteUint64(p.ClientId)

	if err := p.WriteShared(p.TokenData); err != nil {
		return nil, err
	}

	p.TokenData.WriteBytesN(p.UserData, USER_DATA_BYTES)
	return p.TokenData.Buf, nil
}

// Encrypts, in place, the TokenData buffer, assumes Write() has already been called.
func (token *ConnectTokenPrivate) Encrypt(protocolId, expireTimestamp, sequence uint64, privateKey []byte) error {
	additionalData, nonce := buildTokenCryptData(protocolId, expireTimestamp, sequence)
	if err := EncryptAead(&token.TokenData.Buf, additionalData, nonce, privateKey); err != nil {
		return err
	}
	return nil
}

// Decrypts the internal TokenData buffer, assumes that TokenData has been populated with the encrypted data
// (most likely via NewConnectTokenPrivateEncrypted(...)). Optionally returns the decrypted buffer to caller.
func (token *ConnectTokenPrivate) Decrypt(protocolId, expireTimestamp, sequence uint64, privateKey []byte) ([]byte, error) {
	var err error

	additionalData, nonce := buildTokenCryptData(protocolId, expireTimestamp, sequence)
	if token.TokenData.Buf, err = DecryptAead(token.TokenData.Buf, additionalData, nonce, privateKey); err != nil {
		return nil, err
	}
	token.TokenData.Reset() // reset for reads
	return token.TokenData.Buf, nil
}

// Builds the additional data and nonce necessary for encryption and decryption.
func buildTokenCryptData(protocolId, expireTimestamp, sequence uint64) ([]byte, []byte) {
	additionalData := NewBuffer(VERSION_INFO_BYTES + 8 + 8)
	additionalData.WriteBytes([]byte(VERSION_INFO))
	additionalData.WriteUint64(protocolId)
	additionalData.WriteUint64(expireTimestamp)

	nonce := NewBuffer(SizeUint64)
	nonce.WriteUint64(sequence)
	return additionalData.Buf, nonce.Buf
}
