package netcode


type Token interface {
	Encrypt()
	Decrypt()
	Read(buffer []byte, length uint)
	Write(buffer []byte, length uint)
}

type ChallengeToken struct {
	ClientId uint64
	UserData [USER_DATA_BYTES]byte
}

func NewChallengeToken() *ChallengeToken {
	token := &ChallengeToken{}
	return token
}

func (t *ChallengeToken) Encrypt(buffer []byte, length uint, sequence uint64, key []byte) error {
	return nil
}

func (t *ChallengeToken) Decrypt(buffer []byte, length uint, sequence uint64, key []byte) error {
	return nil
}

func (t *ChallengeToken) Read(buffer []byte, length uint) {

}

func (t *ChallengeToken) Write(buffer []byte, length uint) {

}

