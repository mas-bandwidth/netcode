package netcode

import (
	"bytes"
	"net"
	"testing"
)

func TestConnectToken(t *testing.T) {
	var err error
	var tokenBuffer []byte
	var key []byte

	inToken := NewConnectToken()
	server := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	if key, err = GenerateKey(); err != nil {
		t.Fatalf("error generating key %s\n", key)
	}

	config := NewConfig(servers, TEST_TIMEOUT_SECONDS, TEST_CONNECT_TOKEN_EXPIRY, TEST_CLIENT_ID, TEST_PROTOCOL_ID, key)

	// generate will write & encrypt the ConnectTokenPrivate
	err = inToken.Generate(config, TEST_SEQUENCE_START)
	if err != nil {
		t.Fatalf("error generating")
	}

	// Writes the entire ConnectToken (including Private)
	if tokenBuffer, err = inToken.Write(); err != nil {
		t.Fatalf("error writing token: %s\n", err)
	}

	outToken, err := ReadConnectToken(tokenBuffer)
	if err != nil {
		t.Fatalf("error re-reading back token buffer: %s\n", err)
	}

	if string(inToken.VersionInfo) != string(outToken.VersionInfo) {
		t.Fatalf("version info did not match expected: %s got: %s\n", inToken.VersionInfo, outToken.VersionInfo)
	}

	if inToken.ProtocolId != outToken.ProtocolId {
		t.Fatalf("ProtocolId did not match expected: %s got: %s\n", inToken.ProtocolId, outToken.ProtocolId)
	}

	if inToken.CreateTimestamp != outToken.CreateTimestamp {
		t.Fatalf("CreateTimestamp did not match expected: %s got: %s\n", inToken.CreateTimestamp, outToken.CreateTimestamp)
	}

	if inToken.ExpireTimestamp != outToken.ExpireTimestamp {
		t.Fatalf("ExpireTimestamp did not match expected: %s got: %s\n", inToken.ExpireTimestamp, outToken.ExpireTimestamp)
	}

	if inToken.Sequence != outToken.Sequence {
		t.Fatalf("Sequence did not match expected: %s got: %s\n", inToken.Sequence, outToken.Sequence)
	}

	testCompareTokens(inToken, outToken, t)

	if bytes.Compare(inToken.PrivateData.Buffer(), outToken.PrivateData.Buffer()) != 0 {
		t.Fatalf("encrypted private data of tokens did not match\n%#v\n%#v", inToken.PrivateData.Buffer(), outToken.PrivateData.Buffer())
	}

	// need to decrypt the private tokens before we can compare
	if _, err := outToken.PrivateData.Decrypt(config.ProtocolId, outToken.ExpireTimestamp, outToken.Sequence, key); err != nil {
		t.Fatalf("error decrypting private out token data: %s\n", err)
	}

	if _, err := inToken.PrivateData.Decrypt(config.ProtocolId, inToken.ExpireTimestamp, inToken.Sequence, key); err != nil {
		t.Fatalf("error decrypting private in token data: %s\n", err)
	}

	// and re-read to set the properties in outToken private
	if err := outToken.PrivateData.Read(); err != nil {
		t.Fatalf("error reading private data %s", err)
	}

	testComparePrivateTokens(inToken.PrivateData, outToken.PrivateData, t)

}

func testCompareTokens(token1, token2 *ConnectToken, t *testing.T) {
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
