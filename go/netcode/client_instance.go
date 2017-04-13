package netcode

import (
	"net"
)

type ClientInstance struct {
	clientId   uint64
	clientConn *NetcodeConn
	confirmed  bool
	connected  bool

	encryptionIndex  int
	sequence         uint64
	lastSendTime     int64
	lastRecvTime     int64
	userData         []byte
	replayProtection *ReplayProtection
	address          *net.UDPAddr
	connectToken     *ConnectToken
	packetQueue      *PacketQueue
}

func NewClientInstance() *ClientInstance {
	c := &ClientInstance{}
	c.userData = make([]byte, USER_DATA_BYTES)
	c.replayProtection = NewReplayProtection()
	return c
}

func (c *ClientInstance) SendPacket() {

}
