package netcode

import (
	"testing"
	"net"
	"bytes"
	"time"
	"go/token"
)

const (
	TEST_PROTOCOL_ID = 0x1122334455667788
	TEST_CONNECT_TOKEN_EXPIRY = 30
	TEST_SERVER_PORT = 40000
	TEST_CLIENT_ID = 0x1
	TEST_SEQUENCE_START = 1000
)

var TEST_PRIVATE_KEY = []byte{0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
			      0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
			      0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
			      0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 }

func TestNewConnectToken(t *testing.T) {
	token1 := NewConnectToken()
	server := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	config := NewConfig(servers, TEST_CONNECT_TOKEN_EXPIRY, TEST_PROTOCOL_ID, TEST_PRIVATE_KEY)
	currentTimestamp := uint64(time.Now().Unix())

	err := token1.Generate(config, TEST_CLIENT_ID, currentTimestamp, TEST_SEQUENCE_START)
	if err != nil {
		t.Fatalf("error generating and encrypting token")
	}

	private, err := token1.Write()
	if err != nil {
		t.Fatalf("error writing token private data")
	}

	EncryptConnectTokenPrivate(&private, TEST_PROTOCOL_ID, uint64(currentTimestamp + config.TokenExpiry), TEST_SEQUENCE_START, config.PrivateKey)

	token2, err := ReadConnectToken(private, config.ProtocolId, currentTimestamp+config.TokenExpiry, TEST_SEQUENCE_START, config.PrivateKey)
	if err != nil {
		t.Fatalf("error reading connect token %s", err)
	}

	compareTokens(token1, token2, t)

	private2, err := token2.Write()
	if err != nil {
		t.Fatalf("error writing token2 buffer")
	}

	EncryptConnectTokenPrivate(&private2, TEST_PROTOCOL_ID, uint64(currentTimestamp + config.TokenExpiry), TEST_SEQUENCE_START, config.PrivateKey)

	if bytes.Compare(private, private2) != 0 {
		t.Fatalf("encrypted private bits didn't match %v and %v\n", private, private2)
	}
}

func TestConnectTokenPublic(t *testing.T) {
	token1 := NewConnectToken()
	server := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key %s\n", key)
	}

	config := NewConfig(servers, TEST_CONNECT_TOKEN_EXPIRY, TEST_PROTOCOL_ID, key)
	currentTimestamp := uint64(time.Now().Unix())

	err = token1.Generate(config, TEST_CLIENT_ID, currentTimestamp, TEST_SEQUENCE_START)
	if err != nil {
		t.Fatalf("error generating and encrypting token")
	}

	private, err := token1.Write()
	if err != nil {
		t.Fatalf("error writing token private data")
	}

	// write it to a buffer
	EncryptConnectTokenPrivate(&private, TEST_PROTOCOL_ID, uint64(currentTimestamp + config.TokenExpiry), TEST_SEQUENCE_START, config.PrivateKey)

	// set misc public token properties
	token1.TimeoutSeconds = int(TIMEOUT_SECONDS)

	tokenData, err := token1.Write()
	if err != nil {
		t.Fatalf("error writing token: %s\n", err)
	}





}

func compareTokens(token1, token2 *ConnectToken, t *testing.T) {
	if token1.ClientId() != token2.ClientId() {
		t.Fatalf("clientIds do not match expected %d got %d", token1.ClientId, token2.ClientId)
	}

	if len(token1.ServerAddresses()) != len(token2.ServerAddresses()) {
		t.Fatalf("time stamps do not match expected %d got %d", len(token1.ServerAddresses()), len(token2.ServerAddresses()))
	}

	token1Servers := token1.ServerAddresses()
	token2Servers := token2.ServerAddresses()
	for i := 0; i < len(token1.ServerAddresses()); i+=1 {
		if bytes.Compare([]byte(token1Servers[i].IP), []byte(token2Servers[i].IP)) != 0 {
			t.Fatalf("server addresses did not match: expected %v got %v\n", token1Servers[i], token2Servers[i])
		}
	}

	if bytes.Compare(token1.ClientKey(), token2.ClientKey()) != 0 {
		t.Fatalf("ClientKey do not match expected %v got %v", token1.ClientKey(), token2.ClientKey())
	}

	if bytes.Compare(token1.ServerKey(), token2.ServerKey()) != 0 {
		t.Fatalf("ServerKey do not match expected %v got %v", token1.ServerKey(), token2.ServerKey())
	}

}