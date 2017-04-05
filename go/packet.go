package netcode

import (
	"errors"
	"strconv"
	"log"
)

const MAX_CLIENTS = 60
const CONNECT_TOKEN_PRIVATE_BYTES = 1024
const CHALLENGE_TOKEN_BYTES = 300
const VERSION_INFO_BYTES = 13
const USER_DATA_BYTES = 256
const MAX_PACKET_BYTES = 1220
const MAX_PAYLOAD_BYTES = 1200
const MAX_ADDRESS_STRING_LENGTH = 256
const REPLAY_PROTECTION_BUFFER_SIZE = 256
const CLIENT_MAX_RECEIVE_PACKETS = 64
const SERVER_MAX_RECEIVE_PACKETS = ( 64 * MAX_CLIENTS )

const KEY_BYTES = 32
const MAC_BYTES = 16
const NONCE_BYTES = 8
const MAX_SERVERS_PER_CONNECT = 32

const VERSION_INFO = "NETCODE 1.00\x00"


type PacketType uint8

const (
	ConnectionRequest PacketType = iota
	ConnectionDenied
	ConnectionChallenge
	ConnectionResponse
	ConnectionKeepAlive
	ConnectionPayload
	ConnectionDisconnect

)
// not a packet type, but value is last packetType+1
const ConnectionNumPackets = ConnectionDisconnect+1

var packetTypeMap = map[PacketType]string {
	ConnectionRequest: "CONNECTION_REQUEST",
	ConnectionDenied: "CONNECTION_DENIED",
	ConnectionChallenge: "CONNECTION_CHALLENGE",
	ConnectionResponse: "CONNECTION_RESPONSE",
	ConnectionKeepAlive: "CONNECTION_KEEPALIVE",
	ConnectionPayload: "CONNECTION_PAYLOAD",
	ConnectionDisconnect: "CONNECTION_DISCONNECT",
}

type Packet interface {
	GetType() PacketType
}

type RequestPacket struct {
	VersionInfo []byte
	ProtocolId uint64
	ConnectTokenExpireTimestamp uint64
	ConnectTokenSequence uint64
	Token *ConnectToken
	ConnectTokenData []byte // the encrypted Token after Write -> Encrypt
}

func (p *RequestPacket) GetType() PacketType {
	return ConnectionRequest
}

type DeniedPacket struct {
}

func (p *DeniedPacket) GetType() PacketType {
	return ConnectionDenied
}

type ChallengePacket struct {
	ChallengeTokenSequence uint64
	ChallengeTokenData []byte
}

func (p *ChallengePacket) GetType() PacketType {
	return ConnectionChallenge
}

type ResponsePacket struct {
	ChallengeTokenSequence uint64
	ChallengeTokenData []byte
}

func (p *ResponsePacket) GetType() PacketType {
	return ConnectionResponse
}

type KeepAlivePacket struct {
	ClientIndex uint32
	MaxClients uint32
}

func (p *KeepAlivePacket) GetType() PacketType {
	return ConnectionKeepAlive
}


type PayloadPacket struct {
	PayloadBytes uint32
	PayloadData []byte
}

func (p *PayloadPacket) GetType() PacketType {
	return ConnectionPayload
}

func NewPayloadPacket(payloadBytes uint32) *PayloadPacket {
	packet := &PayloadPacket{}
	packet.PayloadBytes = payloadBytes
	packet.PayloadData = make([]byte, payloadBytes)
	return packet
}

type DisconnectPacket struct {
}

func (p *DisconnectPacket) GetType() PacketType {
	return ConnectionDisconnect
}

func WritePacket(packet Packet, buffer *Buffer, sequence uint64, writePacketKey []byte, protocolId uint64) (int, error) {
	packetType := packet.GetType()
	// TODO: this should be moved to writePacketData provided packet prefix can be safely ignored/added
	if packetType == ConnectionRequest {
		// connection request packet: first byte is zero
		p, ok := packet.(*RequestPacket)
		if !ok {
			return -1, errors.New("invalid packet type, expecting request packet")
		}
		buffer.WriteUint8(uint8(ConnectionRequest))
		buffer.WriteBytes(p.VersionInfo)
		buffer.WriteUint64(p.ProtocolId)
		buffer.WriteUint64(p.ConnectTokenExpireTimestamp)
		buffer.WriteUint64(p.ConnectTokenSequence)
		buffer.WriteBytes(p.ConnectTokenData) // write the encrypted connection token private data
		if buffer.Pos != 1 + 13 + 8 + 8 + 8 + CONNECT_TOKEN_PRIVATE_BYTES + MAC_BYTES {
			return -1, errors.New("invalid buffer size written")
		}
		return buffer.Pos, nil
	}

	// *** encrypted packets ***
	prefixByte, err := writePacketPrefix(packet, buffer, sequence)
	if err != nil {
		return -1, err
	}

	encryptedStart := buffer.Pos
	if err := writePacketData(packet, buffer); err != nil {
		return -1, err
	}
	encryptedFinish := buffer.Pos

	additionalData, nonce := packetCryptData(prefixByte, protocolId, sequence)
	log.Printf("data to encrypt size: %d = %d - %d\n", encryptedFinish-encryptedStart, encryptedFinish, encryptedStart)
	// slice up the buffer for the bits we will encrypt
	encryptedBuffer := buffer.Buf[encryptedStart:encryptedFinish]
	if err := EncryptAead(&encryptedBuffer, additionalData, nonce, writePacketKey); err != nil {
		return -1, err
	}

	// hack to reset Pos to write in the encrypted buffer to avoid allocations/append() calls
	buffer.Pos = encryptedStart
	buffer.WriteBytes(encryptedBuffer)
	log.Printf("buffer written so far plus mac: %d\n", buffer.Pos)
	return buffer.Pos, nil // in c, we do Pos + MAC_BYTES but the WriteBytes will update Pos to include it
}

// write the prefix byte (this is a combination of the packet type and number of sequence bytes)
func writePacketPrefix(p Packet, buffer *Buffer, sequence uint64) (uint8, error) {
	sequenceBytes := sequenceNumberBytesRequired(sequence)
	if sequenceBytes < 1 || sequenceBytes > 8 {
		return 0, errors.New("invalid sequence bytes, must be between [1-8]")
	}

	prefixByte := uint8(p.GetType()) | uint8(sequenceBytes << 4)
	buffer.WriteUint8(prefixByte)

	sequenceTemp := sequence

	var i uint8
	for ; i < sequenceBytes; i+=1 {
		buffer.WriteUint8(uint8(sequenceTemp & 0xFF))
		sequenceTemp >>= 8
	}
	return prefixByte, nil
}

// write packet data according to type. this data will be encrypted.
func writePacketData(packet Packet, buffer *Buffer) error {
	switch packet.GetType() {
	case ConnectionDenied:
		// ...
	case ConnectionChallenge:
		p, ok := packet.(*ChallengePacket)
		if !ok {
			return errors.New("invalid packet type")
		}
		buffer.WriteUint64(p.ChallengeTokenSequence)
		buffer.WriteBytesN(p.ChallengeTokenData, CHALLENGE_TOKEN_BYTES)
	case ConnectionResponse:
		p, ok := packet.(*ResponsePacket)
		if !ok {
			return errors.New("invalid packet type")
		}
		buffer.WriteUint64(p.ChallengeTokenSequence)
		buffer.WriteBytesN(p.ChallengeTokenData, CHALLENGE_TOKEN_BYTES)
	case ConnectionKeepAlive:
		p, ok := packet.(*KeepAlivePacket)
		if !ok {
			return errors.New("invalid packet type")
		}
		buffer.WriteUint32(uint32(p.ClientIndex))
		buffer.WriteUint32(uint32(p.MaxClients))
	case ConnectionPayload:
		p, ok := packet.(*PayloadPacket)
		if !ok {
			return errors.New("invalid packet type")
		}
		log.Printf("writing %d payload bytes pre: %d\n", p.PayloadBytes, buffer.Pos)
		buffer.WriteBytesN([]byte(p.PayloadData), int(p.PayloadBytes))
		log.Printf("writing %d payload bytes post: %d\n", p.PayloadBytes, buffer.Pos)
	case ConnectionDisconnect:
		// ...
	}
	return nil
}

// used for encrypting the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.
func packetCryptData(prefixByte uint8, protocolId, sequence uint64) ([]byte, []byte) {
	additionalData := NewBuffer(VERSION_INFO_BYTES+8+1)
	additionalData.WriteBytesN([]byte(VERSION_INFO), VERSION_INFO_BYTES)
	additionalData.WriteUint64(protocolId)
	additionalData.WriteUint8(prefixByte)

	nonce := NewBuffer(SizeUint64)
	nonce.WriteUint64(sequence)
	return additionalData.Buf, nonce.Buf
}

func ReadPacket(packetData []byte, packetLen int, sequence uint64, readPacketKey []byte, protocolId uint64, currentTimestamp uint64, privateKey, allowedPackets []byte, replayProtection *ReplayProtection) (Packet, error) {
	if packetLen < 1 {
		return nil, errors.New("invalid buffer length")
	}

	packetBuffer := NewBufferFromBytes(packetData)

	prefixByte, err := packetBuffer.GetUint8()
	if err != nil {
		return nil, errors.New("invalid buffer length")
	}

	if PacketType(prefixByte) == ConnectionRequest {
		return readRequestPacket(packetBuffer, packetLen, protocolId, currentTimestamp, allowedPackets, privateKey)
	}

	// *** encrypted packets ***
	if readPacketKey == nil {
		return nil, errors.New("empty packet key")
	}

	if packetLen < 1 + 1 + MAC_BYTES {
		return nil, errors.New("ignored encrypted packet. packet is too small to be valid")
	}

	packetType := prefixByte & 0xF

	if PacketType(packetType) >= ConnectionNumPackets {
		return nil, errors.New("ignored encrypted packet. packet type " + packetTypeMap[PacketType(packetType)] + " is invalid")
	}

	if allowedPackets[packetType] == 0 {
		return nil, errors.New("ignored encrypted packet. packet type " + packetTypeMap[PacketType(packetType)] + " is invalid")
	}

	sequenceBytes := prefixByte >> 4
	if sequenceBytes < 1 || sequenceBytes > 8 {
		return nil, errors.New("ignored encrypted packet. sequence bytes is out of range [1,8]")
	}

	if packetLen < 1 + int(sequenceBytes) + MAC_BYTES {
		return nil, errors.New("ignored encrypted packet. buffer is too small for sequence bytes + encryption mac")
	}

	var i uint8
	// read variable length sequence number [1,8]
	for i = 0; i < sequenceBytes; i+=1 {
		val, err := packetBuffer.GetUint8()
		if err != nil {
			return nil, err
		}
		sequence |= uint64((val) << ( 8 * i ))
	}

	// replay protection (optional)
	if replayProtection != nil && PacketType(packetType) >= ConnectionKeepAlive {
		if replayProtection.AlreadyReceived(sequence) == 1 {
			v := strconv.FormatUint(sequence, 10)
			return nil, errors.New("ignored connection payload packet. sequence " + v + " already received (replay protection)")
		}
	}

	// decrypt the per-packet type data
	additionalData, nonce := packetCryptData(prefixByte, protocolId, sequence)

	encryptedSize := packetLen - packetBuffer.Pos
	if encryptedSize < MAC_BYTES {
		return nil, errors.New("ignored encrypted packet. encrypted payload is too small")
	}

	encryptedBuff, err := packetBuffer.GetBytes(encryptedSize)
	if err != nil {
		return nil, errors.New("ignored encrypted packet. encrypted payload is too small")
	}

	decryptedBuff, err := DecryptAead(encryptedBuff, additionalData, nonce, readPacketKey)
	if err != nil {
		return nil, errors.New("ignored encrypted packet. failed to decrypt: " + err.Error())
	}

	decryptedSize := encryptedSize - MAC_BYTES

	// process the per-packet type data that was just decrypted
	return processPacket(PacketType(packetType), decryptedBuff, decryptedSize)
}

// Processes the packet after decryption has occurred.
func processPacket(packetType PacketType, decrypted []byte, decryptedSize int) (Packet, error) {
	var err error
	decryptedBuff := NewBufferFromBytes(decrypted)

	switch packetType {
	case ConnectionDenied:
		if decryptedSize != 0 {
			return nil, errors.New("ignored connection denied packet. decrypted packet data is wrong size")
		}
		return &DeniedPacket{}, nil
	case ConnectionChallenge:
		if decryptedSize != 8 + CHALLENGE_TOKEN_BYTES {
			return nil, errors.New("ignored connection challenge packet. decrypted packet data is wrong size")
		}

		packet := &ChallengePacket{}
		packet.ChallengeTokenSequence, err = decryptedBuff.GetUint64()
		if err != nil {
			return nil, errors.New("error reading challenge token sequence")
		}

		packet.ChallengeTokenData, err = decryptedBuff.GetBytes(CHALLENGE_TOKEN_BYTES)
		if err != nil {
			return nil, errors.New("error reading challenge token data")
		}
		return packet, nil
	case ConnectionResponse:
		if decryptedSize != 8 + CHALLENGE_TOKEN_BYTES {
			return nil, errors.New("ignored connection response packet. decrypted packet data is wrong size")
		}

		packet := &ResponsePacket{}
		packet.ChallengeTokenSequence, err = decryptedBuff.GetUint64()
		if err != nil {
			return nil, errors.New("error reading response token sequence")
		}

		packet.ChallengeTokenData, err = decryptedBuff.GetBytes(CHALLENGE_TOKEN_BYTES)
		if err != nil {
			return nil, errors.New("error reading response token data")
		}
		return packet, nil
	case ConnectionKeepAlive:
		if decryptedSize != 8 {
			return nil, errors.New("ignored connection keep alive packet. decrypted packet data is wrong size")
		}
		packet := &KeepAlivePacket{}
		packet.ClientIndex, err = decryptedBuff.GetUint32()
		if err != nil {
			return nil, errors.New("error reading keepalive client index")
		}

		packet.MaxClients, err = decryptedBuff.GetUint32()
		if err != nil {
			return nil, errors.New("error reading keepalive max clients")
		}
		return packet, nil
	case ConnectionPayload:
		if decryptedSize < 1 {
			return nil, errors.New("ignored connection payload packet. payload is too small")
		}

		if decryptedSize > MAX_PAYLOAD_BYTES {
			return nil, errors.New("ignored connection payload packet. payload is too large")
		}

		packet := NewPayloadPacket(uint32(decryptedSize))
		copy(packet.PayloadData, decryptedBuff.Bytes())
		return packet, nil
	case ConnectionDisconnect:
		if decryptedSize != 0 {
			return nil, errors.New("ignored connection disconnect packet. decrypted packet data is wrong size")
		}
		packet := &DisconnectPacket{}
		return packet, nil
	}

	return nil, errors.New("unknown packet type")
}

// Reads the RequestPacket type returning the packet after deserializing
func readRequestPacket(packetBuffer *Buffer, packetLen int, protocolId, currentTimestamp uint64, allowedPackets []byte, privateKey []byte) (Packet, error) {
	var err error
	packet := &RequestPacket{}

	if allowedPackets[0] == 0 {
		return nil, errors.New("ignored connection request packet. packet type is not allowed")
	}

	if packetLen != 1 + VERSION_INFO_BYTES + 8 + 8 + 8 + CONNECT_TOKEN_PRIVATE_BYTES + MAC_BYTES {
		return nil, errors.New("ignored connection request packet. bad packet length")
	}

	if privateKey == nil {
		return nil, errors.New("ignored connection request packet. no private key\n")
	}

	packet.VersionInfo, err = packetBuffer.GetBytes(VERSION_INFO_BYTES)
	if err != nil {
		return nil, errors.New("ignored connection request packet. bad version info\n")
	}

	if string(packet.VersionInfo) != VERSION_INFO {
		return nil, errors.New("ignored connection request packet. bad version info\n")
	}

	packet.ProtocolId, err = packetBuffer.GetUint64()
	if err != nil || packet.ProtocolId != protocolId {
		return nil, errors.New("ignored connection request packet. wrong protocol id\n")
	}

	packet.ConnectTokenExpireTimestamp, err = packetBuffer.GetUint64()
	if err != nil || packet.ConnectTokenExpireTimestamp <= currentTimestamp {
		return nil, errors.New("ignored connection request packet. connect token expired\n")
	}

	packet.ConnectTokenSequence, err = packetBuffer.GetUint64()
	if err != nil {
		return nil, err
	}

	if packetBuffer.Pos != 1 + VERSION_INFO_BYTES + 8 + 8 + 8 {
		return nil, errors.New(" invalid length of packet buffer read")
	}

	var tokenBuffer []byte
	tokenBuffer, err = packetBuffer.GetBytes(CONNECT_TOKEN_PRIVATE_BYTES+MAC_BYTES)
	if err != nil {
		return nil, err
	}

	packet.Token, err = ReadConnectToken(tokenBuffer, packet.ProtocolId, packet.ConnectTokenExpireTimestamp, packet.ConnectTokenSequence, privateKey)
	if err != nil {
		return nil, err
	}

	return packet, nil
}


func sequenceNumberBytesRequired(sequence uint64) uint8 {
	var mask uint64
	mask = 0xFF00000000000000
	var i uint8
	for ; i < 7; i+=1 {
		if (sequence & mask != 0) {
			break
		}
		mask >>= 8
	}
	return 8 - i
}