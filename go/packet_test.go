package netcode

import (
	"testing"
	"net"
	"time"
	"bytes"
	"crypto/sha1"
)

func TestReadPacket(t *testing.T) {

}

func TestConnectionRequestPacket(t *testing.T) {
	connectTokenKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating connect token key: %s\n", err)
	}
	inputPacket, decryptedToken := testBuildRequestPacket(connectTokenKey, t)
	t.Logf("decrypted len: %#d\n", len(decryptedToken))
	// write the connection request packet to a buffer

	buffer := NewBuffer(2048)

	packetKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key")
	}

	bytesWritten, err := WritePacket(inputPacket, buffer, TEST_SEQUENCE_START, packetKey, TEST_PROTOCOL_ID)
	if err != nil {
		t.Fatalf("error writing packet: %s\n", err)
	}

	if bytesWritten <= 0 {
		t.Fatalf("did not write any bytes for this packet")
	}


	// read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)
	var sequence uint64
	sequence = TEST_SEQUENCE_START

	allowedPackets := make([]byte, ConnectionNumPackets)
	for i := 0; i < len(allowedPackets); i+=1 {
		allowedPackets[i] = 1
	}

	buffer.Reset()
	//t.Logf("before read: %#v %d\n", buffer.Buf[:bytesWritten], len(buffer.Buf[:bytesWritten]))
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), connectTokenKey, allowedPackets, nil)
	if err != nil {
		t.Fatalf("error reading packet: %s\n", err)

	}

	if outputPacket.GetType() != ConnectionRequest {
		t.Fatal("packet output was not a connection request")
	}

	output, ok := outputPacket.(*RequestPacket)
	if !ok {
		t.Fatalf("error casting to connection request packet")
	}

	if bytes.Compare(inputPacket.VersionInfo, output.VersionInfo) != 0 {
		t.Fatalf("version info did not match")
	}

	if inputPacket.ProtocolId != output.ProtocolId {
		t.Fatalf("ProtocolId did not match")
	}

	if inputPacket.ConnectTokenExpireTimestamp != output.ConnectTokenExpireTimestamp {
		t.Fatalf("ConnectTokenExpireTimestamp did not match")
	}

	if inputPacket.ConnectTokenSequence != output.ConnectTokenSequence {
		t.Fatalf("ConnectTokenSequence did not match")
	}

	if bytes.Compare(decryptedToken, output.Token.PrivateData.TokenData.Buf) != 0 {
		t.Fatalf("TokenData did not match")
	}

}

func testBuildRequestPacket(connectTokenKey []byte, t *testing.T) (*RequestPacket, []byte) {
	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: TEST_SERVER_PORT}
	serverAddrs := make([]net.UDPAddr, 1)
	serverAddrs[0] = addr
	config := NewConfig(serverAddrs, TEST_CONNECT_TOKEN_EXPIRY, TEST_PROTOCOL_ID, TEST_PRIVATE_KEY)

	connectToken := NewConnectToken()
	currentTimestamp := uint64(time.Now().Unix())
	expireTimestamp := uint64(time.Now().Unix()) + config.TokenExpiry

	if err := connectToken.Generate(config, TEST_CLIENT_ID, currentTimestamp, TEST_SEQUENCE_START); err != nil {
		t.Fatalf("error generating connect token: %s\n", err)
	}

	privateData, err := connectToken.Write()
	if err != nil {
		t.Fatalf("error writing private data: %s\n", err)
	}

	if err := EncryptConnectTokenPrivate(&privateData, TEST_PROTOCOL_ID, expireTimestamp, TEST_SEQUENCE_START, connectTokenKey); err != nil {
		t.Fatalf("error encrypting connect token private %s\n", err)
	}

	t.Logf("after encrypt test: %x\n", sha1.Sum(privateData))

	decryptedToken, err := DecryptConnectTokenPrivate(privateData, TEST_PROTOCOL_ID, expireTimestamp, TEST_SEQUENCE_START, connectTokenKey)
	if err != nil {
		t.Fatalf("error decrypting connect token: %s", err)
	}

	t.Logf("build request private data len: %d\n", len(privateData))
	_, err = ReadConnectToken(privateData, TEST_PROTOCOL_ID, expireTimestamp, TEST_SEQUENCE_START, connectTokenKey)
	if err != nil {
		t.Fatalf("error reading connect token: %s\n", err)
	}
	// setup a connection request packet wrapping the encrypted connect token
	inputPacket := &RequestPacket{}
	inputPacket.VersionInfo = []byte(VERSION_INFO)
	inputPacket.ProtocolId = TEST_PROTOCOL_ID
	inputPacket.ConnectTokenExpireTimestamp = expireTimestamp
	inputPacket.ConnectTokenSequence = TEST_SEQUENCE_START
	inputPacket.Token = connectToken
	inputPacket.ConnectTokenData = privateData
	return inputPacket, decryptedToken
}