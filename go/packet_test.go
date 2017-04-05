package netcode

import (
	"testing"
	"net"
	"time"
	"bytes"
)

func TestReadPacket(t *testing.T) {

}

func TestSequence(t *testing.T) {
	seq := sequenceNumberBytesRequired(0)
	if seq != 1 {
		t.Fatal("expected 0, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x11)
	if seq != 1 {
		t.Fatal("expected 1, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x1122)
	if seq != 2 {
		t.Fatal("expected 2, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x112233)
	if seq != 3 {
		t.Fatal("expected 3, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x11223344)
	if seq != 4 {
		t.Fatal("expected 4, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x1122334455)
	if seq != 5 {
		t.Fatal("expected 5, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x112233445566)
	if seq != 6 {
		t.Fatal("expected 6, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x11223344556677)
	if seq != 7 {
		t.Fatal("expected 7, got: ", seq)
	}

	seq = sequenceNumberBytesRequired(0x1122334455667788)
	if seq != 8 {
		t.Fatal("expected 8, got: ", seq)
	}

}

func TestConnectionRequestPacket(t *testing.T) {
	connectTokenKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating connect token key: %s\n", err)
	}
	inputPacket, decryptedToken := testBuildRequestPacket(connectTokenKey, t)
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

func TestConnectionDeniedPacket(t *testing.T) {
	// setup a connection denied packet
	inputPacket := &DeniedPacket{}

	buffer := NewBuffer(MAX_PACKET_BYTES)

	packetKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key")
	}

	// write the packet to a buffer
	bytesWritten, err := WritePacket(inputPacket, buffer, TEST_SEQUENCE_START, packetKey, TEST_PROTOCOL_ID)
	if err != nil {
		t.Fatalf("error writing packet: %s\n", err)
	}

	if bytesWritten <= 0 {
		t.Fatalf("did not write any bytes for this packet")
	}

	var sequence uint64
	sequence = TEST_SEQUENCE_START

	allowedPackets := make([]byte, ConnectionNumPackets)
	for i := 0; i < len(allowedPackets); i+=1 {
		allowedPackets[i] = 1
	}

	buffer.Reset()
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), nil, allowedPackets, nil)
	if err != nil {
		t.Fatalf("error reading packet: %s\n", err)
	}
	if outputPacket.GetType() != ConnectionDenied {
		t.Fatalf("did not get a denied packet after read")
	}
}

func TestConnectionChallengePacket(t *testing.T) {
	var err error

	// setup a connection challenge packet
	inputPacket := &ChallengePacket{}
	inputPacket.ChallengeTokenSequence = 0
	inputPacket.ChallengeTokenData, err = RandomBytes(CHALLENGE_TOKEN_BYTES)
	if err != nil {
		t.Fatalf("error generating random bytes")
	}

	buffer := NewBuffer(MAX_PACKET_BYTES)

	packetKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key")
	}

	// write the packet to a buffer
	bytesWritten, err := WritePacket(inputPacket, buffer, TEST_SEQUENCE_START, packetKey, TEST_PROTOCOL_ID)
	if err != nil {
		t.Fatalf("error writing packet: %s\n", err)
	}

	if bytesWritten <= 0 {
		t.Fatalf("did not write any bytes for this packet")
	}

	var sequence uint64
	sequence = TEST_SEQUENCE_START

	allowedPackets := make([]byte, ConnectionNumPackets)
	for i := 0; i < len(allowedPackets); i+=1 {
		allowedPackets[i] = 1
	}

	buffer.Reset()
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), nil, allowedPackets, nil)
	if err != nil {
		t.Fatalf("error reading packet: %s\n", err)
	}

	challenge, ok := outputPacket.(*ChallengePacket)
	if !ok {
		t.Fatalf("did not get a challenge packet after read")
	}

	if inputPacket.ChallengeTokenSequence != challenge.ChallengeTokenSequence {
		t.Fatalf("input and output sequence differed, expected %d got %d\n", inputPacket.ChallengeTokenSequence, challenge.ChallengeTokenSequence)
	}

	if bytes.Compare(inputPacket.ChallengeTokenData, challenge.ChallengeTokenData) != 0 {
		t.Fatalf("challenge token data was not equal\n")
	}
}

func TestConnectionResponsePacket(t *testing.T) {
	var err error

	// setup a connection challenge packet
	inputPacket := &ResponsePacket{}
	inputPacket.ChallengeTokenSequence = 0
	inputPacket.ChallengeTokenData, err = RandomBytes(CHALLENGE_TOKEN_BYTES)
	if err != nil {
		t.Fatalf("error generating random bytes")
	}

	buffer := NewBuffer(MAX_PACKET_BYTES)

	packetKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key")
	}

	// write the packet to a buffer
	bytesWritten, err := WritePacket(inputPacket, buffer, TEST_SEQUENCE_START, packetKey, TEST_PROTOCOL_ID)
	if err != nil {
		t.Fatalf("error writing packet: %s\n", err)
	}

	if bytesWritten <= 0 {
		t.Fatalf("did not write any bytes for this packet")
	}

	var sequence uint64
	sequence = TEST_SEQUENCE_START

	allowedPackets := make([]byte, ConnectionNumPackets)
	for i := 0; i < len(allowedPackets); i+=1 {
		allowedPackets[i] = 1
	}

	buffer.Reset()
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), nil, allowedPackets, nil)
	if err != nil {
		t.Fatalf("error reading packet: %s\n", err)
	}

	response, ok := outputPacket.(*ResponsePacket)
	if !ok {
		t.Fatalf("did not get a response packet after read")
	}

	if inputPacket.ChallengeTokenSequence != response.ChallengeTokenSequence {
		t.Fatalf("input and output sequence differed, expected %d got %d\n", inputPacket.ChallengeTokenSequence, response.ChallengeTokenSequence)
	}

	if bytes.Compare(inputPacket.ChallengeTokenData, response.ChallengeTokenData) != 0 {
		t.Fatalf("challenge token data was not equal\n")
	}
}


func TestConnectionKeepAlivePacket(t *testing.T) {
	var err error

	// setup a connection challenge packet
	inputPacket := &KeepAlivePacket{}
	inputPacket.ClientIndex = 10
	inputPacket.MaxClients = 16

	buffer := NewBuffer(MAX_PACKET_BYTES)

	packetKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key")
	}

	// write the packet to a buffer
	bytesWritten, err := WritePacket(inputPacket, buffer, TEST_SEQUENCE_START, packetKey, TEST_PROTOCOL_ID)
	if err != nil {
		t.Fatalf("error writing packet: %s\n", err)
	}

	if bytesWritten <= 0 {
		t.Fatalf("did not write any bytes for this packet")
	}

	var sequence uint64
	sequence = TEST_SEQUENCE_START

	allowedPackets := make([]byte, ConnectionNumPackets)
	for i := 0; i < len(allowedPackets); i+=1 {
		allowedPackets[i] = 1
	}

	buffer.Reset()
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), nil, allowedPackets, nil)
	if err != nil {
		t.Fatalf("error reading packet: %s\n", err)
	}

	keepalive, ok := outputPacket.(*KeepAlivePacket)
	if !ok {
		t.Fatalf("did not get a response packet after read")
	}

	if inputPacket.ClientIndex != keepalive.ClientIndex {
		t.Fatalf("input and output index differed, expected %d got %d\n", inputPacket.ClientIndex, keepalive.ClientIndex)
	}

	if inputPacket.MaxClients != keepalive.MaxClients {
		t.Fatalf("input and output maxclients differed, expected %d got %d\n", inputPacket.MaxClients, keepalive.MaxClients)
	}
}

func TestConnectionPayloadPacket(t *testing.T) {
	var err error

	// setup a connection challenge packet
	inputPacket := 	NewPayloadPacket(MAX_PAYLOAD_BYTES)
	inputPacket.PayloadData, err = RandomBytes(MAX_PAYLOAD_BYTES)
	if err != nil {
		t.Fatalf("error generating random payload data: %s\n", err)
	}

	buffer := NewBuffer(MAX_PACKET_BYTES)

	packetKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key")
	}

	// write the packet to a buffer
	bytesWritten, err := WritePacket(inputPacket, buffer, TEST_SEQUENCE_START, packetKey, TEST_PROTOCOL_ID)
	if err != nil {
		t.Fatalf("error writing packet: %s\n", err)
	}

	if bytesWritten <= 0 {
		t.Fatalf("did not write any bytes for this packet")
	}

	var sequence uint64
	sequence = TEST_SEQUENCE_START

	allowedPackets := make([]byte, ConnectionNumPackets)
	for i := 0; i < len(allowedPackets); i+=1 {
		allowedPackets[i] = 1
	}

	buffer.Reset()
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), nil, allowedPackets, nil)
	if err != nil {
		t.Fatalf("error reading packet: %s\n", err)
	}

	payload, ok := outputPacket.(*PayloadPacket)
	if !ok {
		t.Fatalf("did not get a payload packet after read")
	}

	if inputPacket.PayloadBytes != payload.PayloadBytes {
		t.Fatalf("input and output index differed, expected %d got %d\n", inputPacket.PayloadBytes, payload.PayloadBytes)
	}

	if bytes.Compare(inputPacket.PayloadData, payload.PayloadData) != 0 {
		t.Fatalf("input and output payload differed, expected %v got %v\n", inputPacket.PayloadData, payload.PayloadData)
	}
}

func TestDisconnectPacket(t *testing.T) {
	inputPacket := &DisconnectPacket{}
	buffer := NewBuffer(MAX_PACKET_BYTES)

	packetKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("error generating key")
	}

	// write the packet to a buffer
	bytesWritten, err := WritePacket(inputPacket, buffer, TEST_SEQUENCE_START, packetKey, TEST_PROTOCOL_ID)
	if err != nil {
		t.Fatalf("error writing packet: %s\n", err)
	}

	if bytesWritten <= 0 {
		t.Fatalf("did not write any bytes for this packet")
	}

	var sequence uint64
	sequence = TEST_SEQUENCE_START

	allowedPackets := make([]byte, ConnectionNumPackets)
	for i := 0; i < len(allowedPackets); i+=1 {
		allowedPackets[i] = 1
	}

	buffer.Reset()
	outputPacket, err := ReadPacket(buffer.Buf, bytesWritten, sequence, packetKey, TEST_PROTOCOL_ID, uint64(time.Now().Unix()), nil, allowedPackets, nil)
	if err != nil {
		t.Fatalf("error reading packet: %s\n", err)
	}

	_, ok := outputPacket.(*DisconnectPacket)
	if !ok {
		t.Fatalf("did not get a disconnect packet after read")
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

	decryptedToken, err := DecryptConnectTokenPrivate(privateData, TEST_PROTOCOL_ID, expireTimestamp, TEST_SEQUENCE_START, connectTokenKey)
	if err != nil {
		t.Fatalf("error decrypting connect token: %s", err)
	}

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