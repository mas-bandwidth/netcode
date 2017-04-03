package netcode

import (
	"crypto/rand"
	"github.com/codahale/chacha20poly1305"
	"log"
)

// Generates random bytes
func RandomBytes(bytes int) ([]byte, error) {
	b := make([]byte, bytes)
	_, err := rand.Read(b)
	return b, err
}

// Generates a random key of KEY_BYTES
func GenerateKey() ([]byte, error) {
	return RandomBytes(KEY_BYTES)
}

// Encrypts the message in place with the nonce and key and optional additional buffer
func EncryptAead(message *[]byte, additional []byte, nonce, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	log.Printf("before seal: %#v\n", message)
	*message = aead.Seal(nil, nonce, *message, additional)
	log.Printf("after seal: %#v\n", message)
	return nil
}

// Encrypts the message with the nonce and key and optional additional buffer returning a copy
// byte slice
func DecryptAead(message []byte, additional []byte, nonce, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)

	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, message, additional)
}