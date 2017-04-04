package netcode

import (
	"testing"
	"net"
	"time"
	"bytes"
)

func TestReadPacket(t *testing.T) {

}

func TestConnectionRequestPacket(t *testing.T) {
	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: TEST_SERVER_PORT}
	serverAddrs := make([]net.UDPAddr, 1)
	serverAddrs[0] = addr
	config := NewConfig(serverAddrs, TEST_CONNECT_TOKEN_EXPIRY, TEST_PROTOCOL_ID, TEST_PRIVATE_KEY)

	connectToken := NewConnectToken()
	currentTimestamp := uint64(time.Now().Unix())

	if err := connectToken.Generate(config, TEST_CLIENT_ID, currentTimestamp, TEST_SEQUENCE_START); err != nil {
		t.Fatalf("error generating connect token: %s\n", err)
	}

	// setup a connection request packet wrapping the encrypted connect token
	inputPacket := &RequestPacket{}
	inputPacket.VersionInfo = []byte(VERSION_INFO)
	inputPacket.ProtocolId = TEST_PROTOCOL_ID
	inputPacket.ConnectTokenExpireTimestamp = uint64(time.Now().Unix() + 30)
	inputPacket.ConnectTokenSequence = TEST_SEQUENCE_START
	inputPacket.ConnectTokenData = connectToken.PrivateData.TokenData.Bytes()

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
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), TEST_PRIVATE_KEY, allowedPackets, nil)
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

	if bytes.Compare(inputPacket.Token.PrivateData.TokenData.Buf, output.Token.PrivateData.TokenData.Buf) != 0 {
		t.Fatalf("TokenData did not match")
	}

}
