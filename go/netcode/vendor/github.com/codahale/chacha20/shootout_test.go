package chacha20_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"testing"

	"github.com/codahale/chacha20"
)

const benchSize = 1024 * 1024

func benchmarkStream(b *testing.B, c cipher.Stream) {
	b.SetBytes(benchSize)
	input := make([]byte, benchSize)
	output := make([]byte, benchSize)
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(output, input)
	}
}

func BenchmarkChaCha20(b *testing.B) {
	key := make([]byte, chacha20.KeySize)
	nonce := make([]byte, chacha20.NonceSize)
	c, _ := chacha20.New(key, nonce)
	benchmarkStream(b, c)
}

func BenchmarkAESCTR(b *testing.B) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)

	iv := make([]byte, aes.BlockSize)
	c := cipher.NewCTR(a, iv)

	benchmarkStream(b, c)
}

func BenchmarkRC4(b *testing.B) {
	key := make([]byte, 32)
	c, _ := rc4.NewCipher(key)
	benchmarkStream(b, c)
}
