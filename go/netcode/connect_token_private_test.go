package netcode

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestConnectTokenPrivate(t *testing.T) {
	token1 := NewConnectTokenPrivate()
	server := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	config := NewConfig(servers, TEST_TIMEOUT_SECONDS, TEST_CONNECT_TOKEN_EXPIRY, TEST_CLIENT_ID, TEST_PROTOCOL_ID, TEST_PRIVATE_KEY)
	currentTimestamp := uint64(time.Now().Unix())
	expireTimestamp := uint64(currentTimestamp + config.TokenExpiry)

	userData, err := RandomBytes(USER_DATA_BYTES)
	if err != nil {
		t.Fatalf("error generating random bytes: %s\n", err)
	}

	if err := token1.Generate(config, userData); err != nil {
		t.Fatalf("error generating and encrypting token")
	}

	if _, err := token1.Write(); err != nil {
		t.Fatalf("error writing token private data")
	}

	if err := token1.Encrypt(config.ProtocolId, expireTimestamp, TEST_SEQUENCE_START, config.PrivateKey); err != nil {
		t.Fatalf("error encrypting token: %s\n", err)
	}

	token2 := NewConnectTokenPrivate()
	token2.TokenData = NewBufferFromBytes(token1.Buffer())

	if _, err := token2.Decrypt(config.ProtocolId, expireTimestamp, TEST_SEQUENCE_START, config.PrivateKey); err != nil {
		t.Fatalf("error decrypting token: %s", err)
	}

	if err := token2.Read(); err != nil {
		t.Fatalf("error reading token: %s\n", err)
	}

	testComparePrivateTokens(token1, token2, t)

	token2.TokenData.Reset()
	if _, err = token2.Write(); err != nil {
		t.Fatalf("error writing token2 buffer")
	}

	if err := token2.Encrypt(config.ProtocolId, expireTimestamp, TEST_SEQUENCE_START, config.PrivateKey); err != nil {
		t.Fatalf("error encrypting second token: %s\n", err)
	}

	if len(token1.Buffer()) != len(token2.Buffer()) {
		t.Fatalf("encrypted buffer lengths did not match %d and %d\n", len(token1.Buffer()), len(token2.Buffer()))
	}

	if bytes.Compare(token1.Buffer(), token2.Buffer()) != 0 {
		t.Fatalf("encrypted private bits didn't match\n%#v\n and\n%#v\n", token1.Buffer(), token2.Buffer())
	}
}

func testComparePrivateTokens(token1, token2 *ConnectTokenPrivate, t *testing.T) {
	if token1.ClientId != token2.ClientId {
		t.Fatalf("clientIds do not match expected %d got %d", token1.ClientId, token2.ClientId)
	}

	if len(token1.ServerAddrs) != len(token2.ServerAddrs) {
		t.Fatalf("time stamps do not match expected %d got %d", len(token1.ServerAddrs), len(token2.ServerAddrs))
	}

	token1Servers := token1.ServerAddrs
	token2Servers := token2.ServerAddrs
	for i := 0; i < len(token1.ServerAddrs); i += 1 {
		if bytes.Compare([]byte(token1Servers[i].IP), []byte(token2Servers[i].IP)) != 0 {
			t.Fatalf("server addresses did not match: expected %v got %v\n", token1Servers[i], token2Servers[i])
		}
	}

	if bytes.Compare(token1.ClientKey, token2.ClientKey) != 0 {
		t.Fatalf("ClientKey do not match expected %v got %v", token1.ClientKey, token2.ClientKey)
	}

	if bytes.Compare(token1.ServerKey, token2.ServerKey) != 0 {
		t.Fatalf("ServerKey do not match expected %v got %v", token1.ServerKey, token2.ServerKey)
	}
}
