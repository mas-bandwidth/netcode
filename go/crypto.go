package netcode

import (
	"crypto/rand"
	"github.com/codahale/chacha20poly1305"
	//"log"
	"crypto/sha1"
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
func EncryptAead(message *[]byte, additional, nonce, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	*message = aead.Seal(nil, nonce, *message, additional)
	log.Printf("AFTER ENCRYPT: %x %x %x %x\n", sha1.Sum(*message), sha1.Sum(additional), sha1.Sum(nonce), sha1.Sum(key))
	return nil
}

// Decrypts the message with the nonce and key and optional additional buffer returning a copy
// byte slice
func DecryptAead(message []byte, additional, nonce, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	log.Printf("BEFORE DECRYPT: %x %x %x %x\n", sha1.Sum(message), sha1.Sum(additional), sha1.Sum(nonce), sha1.Sum(key))
	return aead.Open(nil, nonce, message, additional)
}