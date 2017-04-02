package netcode

import (
	"testing"
	"net"
	"bytes"
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
	token := NewConnectToken()
	server := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server
	config := NewConfig(servers, TEST_CONNECT_TOKEN_EXPIRY, TEST_PROTOCOL_ID, TEST_PRIVATE_KEY)
	err := token.Generate(config, TEST_SEQUENCE_START, TEST_CLIENT_ID)
	if err != nil {
		t.Fatalf("error generating token")
	}

	err = token.Decrypt(config.ProtocolId, TEST_SEQUENCE_START, config.PrivateKey)
	if err != nil {
		t.Fatalf("error decrypting token: %s\n", err)
	}

	token2, err := ReadToken(token.TokenData.Buf)

	if token.ClientId != token2.ClientId {
		t.Fatalf("clientIds do not match expected %d got %d", token.ClientId, token2.ClientId)
	}

	if len(token.ServerAddresses) != len(token2.ServerAddresses) {
		t.Fatalf("time stamps do not match expected %d got %d", len(token.ServerAddresses), len(token2.ServerAddresses))
	}

	// TODO verify server addresses

	if bytes.Compare(token.ClientKey, token2.ClientKey) != 0 {
		t.Fatalf("ClientKey do not match expected %v got %v", token.ClientKey, token2.ClientKey)
	}

	if bytes.Compare(token.ServerKey, token2.ServerKey) != 0 {
		t.Fatalf("ServerKey do not match expected %v got %v", token.ServerKey, token2.ServerKey)
	}

	if bytes.Compare(token.UserData, token2.UserData) != 0 {
		t.Fatalf("UserData do not match expected %v got %v", token.UserData, token2.UserData)
	}
}