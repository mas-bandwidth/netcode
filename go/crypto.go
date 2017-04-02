package netcode

import (
	"crypto/rand"
	"github.com/codahale/chacha20poly1305"
	"log"
)

func RandomBytes(bytes int) ([]byte, error) {
	b := make([]byte, bytes)
	_, err := rand.Read(b)
	return b, err
}

func GenerateKey() ([]byte, error) {
	return RandomBytes(KEY_BYTES)
}


func EncryptAead(message *[]byte, additional []byte, nonce, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	log.Printf("before seal: %#v\n", message)
	*message = aead.Seal(nil, nonce, *message, additional)
	return nil
}

func DecryptAead(message []byte, additional []byte, nonce, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)

	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, message, additional)
}