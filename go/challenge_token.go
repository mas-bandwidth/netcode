package netcode

// Challenge tokens are used in certain packet types
type ChallengeToken struct {
	ClientId uint64 // the clientId associated with this token
	UserData *Buffer // the userdata payload
	TokenData *Buffer // the serialized payload container
}

// Creates a new empty challenge token with only the clientId set
func NewChallengeToken(clientId uint64) *ChallengeToken {
	token := &ChallengeToken{}
	token.ClientId = clientId
	token.UserData = NewBuffer(USER_DATA_BYTES)
	token.TokenData = NewBuffer(CHALLENGE_TOKEN_BYTES)
	return token
}

// Encrypts the TokenData buffer with the sequence nonce and provided key
func (t *ChallengeToken) Encrypt(sequence uint64, key []byte) error {
	nonce := NewBuffer(SizeUint64)
	nonce.WriteUint64(sequence)

	return EncryptAead(&t.TokenData.Buf, nil, nonce.Bytes(), key)
}

// Decrypts the TokenData buffer with the sequence nonce and provided key, updating the
// internal TokenData buffer
func (t *ChallengeToken) Decrypt(sequence uint64, key []byte) error {
	var err error
	nonce := NewBuffer(SizeUint64)
	nonce.WriteUint64(sequence)
	t.TokenData.Buf, err = DecryptAead(t.TokenData.Buf, nil, nonce.Bytes(), key)
	return err
}

// Serializes the client id and userData, also sets the UserData buffer.
func (t *ChallengeToken) Write(userData []byte) {
	t.UserData.WriteBytes(userData)

	t.TokenData.WriteUint64(t.ClientId)
	t.TokenData.WriteBytes(userData)
}

// Generates a new ChallengeToken from the provided buffer byte slice. Only sets the ClientId
// and UserData buffer, does not update the TokenData buffer.
func ReadChallengeToken(buffer []byte) (*ChallengeToken, error) {
	var err error
	var clientId uint64
	var userData []byte
	tokenBuffer := NewBufferFromBytes(buffer)

	clientId, err = tokenBuffer.GetUint64()
	if err != nil {
		return nil, err
	}
	token := NewChallengeToken(clientId)

	userData, err = tokenBuffer.GetBytes(USER_DATA_BYTES)
	if err != nil {
		return nil, err
	}
	token.UserData.WriteBytes(userData)
	token.UserData.Reset()

	return token, nil
}
