package netcode

import (
	"log"
	"errors"
)

type PacketType uint8

const MAX_CLIENTS = 60
const CONNECT_TOKEN_PRIVATE_BYTES = 1024
const CHALLENGE_TOKEN_BYTES = 300
const VERSION_INFO_BYTES = 13
const USER_DATA_BYTES = 256
const MAX_PACKET_BYTES = 1220
const MAX_PAYLOAD_BYTES = 1200
const MAX_ADDRESS_STRING_LENGTH = 256
const PACKET_QUEUE_SIZE = 256
const REPLAY_PROTECTION_BUFFER_SIZE = 256
const CLIENT_MAX_RECEIVE_PACKETS = 64
const SERVER_MAX_RECEIVE_PACKETS = ( 64 * MAX_CLIENTS )

const KEY_BYTES = 32
const MAC_BYTES = 16
const NONCE_BYTES = 8
const MAX_SERVERS_PER_CONNECT = 32

const VERSION_INFO = "NETCODE 1.00"
const PACKET_SEND_RATE = 10.0
const TIMEOUT_SECONDS = 5.0
const NUM_DISCONNECT_PACKETS = 10


const (
	ConnectionRequest PacketType = iota
	ConnectionDenied
	ConnectionChallenge
	ConnectionResponse
	ConnectionKeepAlive
	ConnectionPayload
	ConnectionDisconnect
	ConnectionNumPackets
)

type Packet interface {
	GetType() PacketType
}

type RequestPacket struct {
	Type PacketType
	VersionInfo []byte
	ProtocolId uint64
	ConnectTokenExpireTimestamp uint64
	ConnectTokenSequence uint64
	ConnectTokenData []byte
}

func (p *RequestPacket) GetType() PacketType {
	return ConnectionRequest
}

type DeniedPacket struct {
	Type PacketType
}

func (p *DeniedPacket) GetType() PacketType {
	return ConnectionDenied
}

type ChallengePacket struct {
	Type PacketType
	ChallengeTokenSequence uint64
	ChallengeTokenData []byte
}

func (p *ChallengePacket) GetType() PacketType {
	return ConnectionChallenge
}

type ResponsePacket struct {
	Type PacketType
	ChallengeTokenSequence uint64
	ChallengeTokenData []byte
}

func (p *ResponsePacket) GetType() PacketType {
	return ConnectionResponse
}

type KeepAlivePacket struct {
	Type PacketType
	ClientIndex uint
	MaxClients uint
}

func (p *KeepAlivePacket) GetType() PacketType {
	return ConnectionKeepAlive
}


type PayloadPacket struct {
	Type PacketType
	PayloadBytes uint32
	PayloadData []byte
	// ...
}

func (p *PayloadPacket) GetType() PacketType {
	return ConnectionPayload
}

func NewPayloadPacket(payload_bytes uint32) *PayloadPacket {
	return &PayloadPacket{Type: ConnectionPayload, PayloadBytes: payload_bytes}
}

type DisconnectPacket struct {
	Type PacketType
}

type Context struct {
	WritePacketKey []byte
	ReadPacketKey []byte
}

type ReplayProtection struct {
	MostRecentSequence uint64
	ReceivedPacket []uint64
}

func (r *ReplayProtection) Reset() {
	r.MostRecentSequence = 0
	//MemsetUint64(r.ReceivedPacket, 0xFF)
}

func (r *ReplayProtection) AlreadyReceived(sequence uint64) int {
	if (sequence & 1 << 63) == 0 {
		return 0
	}

	if sequence + REPLAY_PROTECTION_BUFFER_SIZE <= r.MostRecentSequence {
		return 1
	}

	if  sequence > r.MostRecentSequence {
		r.MostRecentSequence = sequence
	}

	index := ( sequence % REPLAY_PROTECTION_BUFFER_SIZE)

	if r.ReceivedPacket[index] == 0xFFFFFFFFFFFFFFFF {
		r.ReceivedPacket[index] = sequence
		return 0
	}

	if r.ReceivedPacket[index] >= sequence {
		return 1
	}

	r.ReceivedPacket[index] = sequence
	return 0
}

func SequenceNumberBytesRequired(sequence uint64) int {
	var mask uint64
	mask = 0xFF00000000000000
	i := 0
	for ; i < 7; i+=1 {
		if (sequence & mask == 0) {
			break
		}
		mask >>= 8
	}
	return 8 - i
}

func WritePacket(packet Packet, buffer *Buffer, buffer_length uint, sequence uint64, write_packet_key []byte, protocol_id uint64) (int, error) {
	var p Packet
	var start *Buffer

	packetType := packet.GetType()

	if packetType == ConnectionRequest {

		p, ok := packet.(*RequestPacket)
		if !ok {
			return -1, nil
		}
		start = NewBufferFromBytes(buffer.Bytes())
		buffer.WriteUint8(uint8(ConnectionRequest))
		buffer.WriteBytesN(p.VersionInfo, VERSION_INFO_BYTES)
		buffer.WriteUint64(p.ProtocolId)
		buffer.WriteUint64(p.ConnectTokenExpireTimestamp)
		buffer.WriteUint64(p.ConnectTokenSequence)
		buffer.WriteBytesN(p.ConnectTokenData, CONNECT_TOKEN_PRIVATE_BYTES)
		return buffer.Len() - start.Len(), nil
	}

	// *** encrypted packets ***

	// write the prefix byte (this is a combination of the packet type and number of sequence bytes)
	start = NewBufferFromBytes(buffer.Bytes())
	sequence_bytes := SequenceNumberBytesRequired(sequence)

	prefix_byte := uint8(p.GetType()) | uint8(sequence_bytes << 4)
	buffer.WriteUint8(prefix_byte)

	sequence_temp := sequence

	for i := 0; i < sequence_bytes; i+=1 {
		buffer.WriteUint8(uint8(sequence_temp & 0xFF))
		sequence_temp >>= 8
	}

	//encrypted_start := NewBufferFromBytes(buffer.Buf.Bytes())

	switch (p.GetType()) {
	case ConnectionDenied:
		// ...
	case ConnectionChallenge:
		p, ok := packet.(*ChallengePacket)
		if !ok {
			return -1, nil
		}
		buffer.WriteUint64(p.ChallengeTokenSequence)
		buffer.WriteBytesN(p.ChallengeTokenData, CHALLENGE_TOKEN_BYTES)
	case ConnectionResponse:
		p, ok := packet.(*ResponsePacket)
		if !ok {
			return -1, nil
		}
		buffer.WriteUint64(p.ChallengeTokenSequence)
		buffer.WriteBytesN(p.ChallengeTokenData, CHALLENGE_TOKEN_BYTES)
	case ConnectionKeepAlive:
		p, ok := packet.(*KeepAlivePacket)
		if !ok {
			return -1, nil
		}
		buffer.WriteUint32(uint32(p.ClientIndex))
		buffer.WriteUint32(uint32(p.MaxClients))
	case ConnectionPayload:
		p, ok := packet.(*PayloadPacket)
		if !ok {
			return -1, nil
		}
		buffer.WriteBytesN([]byte(p.PayloadData), int(p.PayloadBytes))
	case ConnectionDisconnect:
		// ...
	}
	//encrypted_finish := buffer


	// encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.
	additional_data := NewBuffer(VERSION_INFO_BYTES+8+1)
	additional_data.WriteBytesN([]byte(VERSION_INFO), VERSION_INFO_BYTES)

	nonce := NewBuffer(8)

	nonce.WriteUint64(sequence)

	//err := EncryptAead(encrypted_start, len(encrypted_finish) - len(encrypted_start), additional_data, len(additional_data), nonce, write_packet_key)
	//if err != nil {
	//	return -1, err
	//}

	// buffer += MAC_BYTES ???

	return buffer.Len() - start.Len(), nil
}

func ReadPacket(buffer *Buffer, buffer_length int, sequence uint64, read_packet_key []byte, protocol_id uint64, current_timestamp uint64, private_key []byte, allowed_packets []byte, replay_protection *ReplayProtection) (Packet, error) {
	var packet Packet
	sequence = 0
	if buffer_length < 1 {
		return nil, errors.New("invalid buffer length")
	}

	//start := NewBufferFromBytes(buffer.Buf.Bytes())

	prefix_byte, err := buffer.GetUint8()
	if err != nil {
		return nil, errors.New("invalid buffer length")
	}

	if PacketType(prefix_byte) == ConnectionRequest {
		if allowed_packets[0] != 0 {
			return nil, errors.New("ignored connection request packet. packet type is not allowed\n")
		}

		if buffer_length != 1 + VERSION_INFO_BYTES + 8 + 8 + 8 + CONNECT_TOKEN_PRIVATE_BYTES {
			return nil, errors.New("ignored connection request packet. bad packet length\n")
		}

		if private_key == nil {
			return nil, errors.New("ignored connection request packet. no private key\n")
		}

		version_info, err := buffer.GetBytes(VERSION_INFO_BYTES)
		if err != nil {
			return nil, errors.New("ignored connection request packet. bad version info\n")
		}

		if string(version_info) != VERSION_INFO {
			return nil, errors.New("ignored connection request packet. bad version info\n")
		}

		id, err := buffer.GetUint64()
		if err != nil || id != protocol_id {
			return nil, errors.New("ignored connection request packet. wrong protocol id\n")
		}

		expire, err := buffer.GetUint64()
		if err != nil || expire <= current_timestamp {
			return nil, errors.New("ignored connection request packet. connect token expired\n")
		}

		token_sequence, err := buffer.GetUint64()
		if err != nil {
			return nil, err
		}
		log.Print(token_sequence)
		return packet, nil
	}
	return packet, nil
}