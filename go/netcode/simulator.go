package netcode


const PACKET_SEND_RATE = 10.0
const TIMEOUT_SECONDS = 5.0
const NUM_DISCONNECT_PACKETS = 10


type Context struct {
	WritePacketKey []byte
	ReadPacketKey []byte
}
