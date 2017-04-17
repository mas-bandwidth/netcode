package netcode

import (
	"errors"
	"log"
	"net"
)

type ClientInstance struct {
	clientId    uint64
	clientIndex int
	serverConn  *NetcodeConn
	confirmed   bool
	connected   bool

	encryptionIndex  int
	sequence         uint64
	lastSendTime     float64
	lastRecvTime     float64
	userData         []byte
	protocolId       uint64
	replayProtection *ReplayProtection
	address          *net.UDPAddr
	connectToken     *ConnectToken
	packetQueue      *PacketQueue
}

func NewClientInstance() *ClientInstance {
	c := &ClientInstance{}
	c.userData = make([]byte, USER_DATA_BYTES)
	c.packetQueue = NewPacketQueue(PACKET_QUEUE_SIZE)
	c.replayProtection = NewReplayProtection()
	return c
}

func (c *ClientInstance) Clear() {
	c.replayProtection.Reset()
	c.connected = false
	c.confirmed = false
	c.clientId = 0
	c.sequence = 0
	c.lastSendTime = 0.0
	c.lastRecvTime = 0.0
	c.address = nil
	c.clientIndex = -1
	c.encryptionIndex = -1
	c.packetQueue.Clear()
	c.userData = make([]byte, USER_DATA_BYTES)
}

func (c *ClientInstance) SendPacket(packet Packet, writePacketKey []byte, serverTime float64) error {
	var bytesWritten int
	var err error

	packetBuffer := NewBuffer(MAX_PACKET_BYTES)

	if bytesWritten, err = packet.Write(packetBuffer, c.protocolId, c.sequence, writePacketKey); err != nil {
		return errors.New("error: unable to write packet: " + err.Error())
	}

	if _, err := c.serverConn.WriteTo(packetBuffer.Buf[:bytesWritten], c.address); err != nil {
		log.Printf("error writing to client: %s\n", err)
	}
	log.Printf("write %s to: %s\n", packetTypeMap[packet.GetType()], c.address.String())
	c.sequence++
	c.lastSendTime = serverTime
	return nil
}
