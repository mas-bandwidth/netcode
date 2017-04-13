package netcode

import (
	"errors"
	"log"
	"net"
	"time"
)

const CLIENT_MAX_RECEIVE_PACKETS = 64
const SERVER_MAX_RECEIVE_PACKETS = (64 * MAX_CLIENTS)
const PACKET_SEND_RATE = 10
const TIMEOUT_SECONDS = 5
const NUM_DISCONNECT_PACKETS = 10

type Context struct {
	WritePacketKey []byte
	ReadPacketKey  []byte
}

type ClientState int8

const (
	StateTokenExpired               ClientState = -6
	StateInvalidConnectToken                    = -5
	StateConnectionTimedOut                     = -4
	StateConnectionResponseTimedOut             = -3
	StateConnectionRequestTimedOut              = -2
	StateConnectionDenied                       = -1
	StateDisconnected                           = 0
	StateSendingConnectionRequest               = 1
	StateSendingConnectionResponse              = 2
	StateConnected                              = 3
)

var clientStateMap = map[ClientState]string{
	StateTokenExpired:               "connect token expired",
	StateInvalidConnectToken:        "invalid connect token",
	StateConnectionTimedOut:         "connection timed out",
	StateConnectionResponseTimedOut: "connection response timed out",
	StateConnectionRequestTimedOut:  "connection request timed out",
	StateConnectionDenied:           "connection denied",
	StateDisconnected:               "disconnected",
	StateSendingConnectionRequest:   "sending connection request",
	StateSendingConnectionResponse:  "sending connection response",
	StateConnected:                  "connected",
}

type Client struct {
	id     uint64
	config *Config

	time                  int64
	startTime             int64
	lastPacketSendTime    int64
	lastPacketRecvTime    int64
	shouldDisconnect      bool
	state                 ClientState
	shouldDisconnectState ClientState
	sequence              uint64
	challengeSequence     uint64

	clientIndex   uint32
	maxClients    uint32
	serverIndex   int
	address       *net.UDPAddr
	serverAddress *net.UDPAddr

	challengeData    []byte
	connectToken     *ConnectToken
	context          *Context
	replayProtection *ReplayProtection
	conn             *NetcodeConn
	packetQueue      *PacketQueue
}

func NewClient(config *Config) *Client {
	c := &Client{config: config}
	c.lastPacketRecvTime = time.Now().Unix() - 1000
	c.lastPacketSendTime = time.Now().Unix() - 1000
	c.setState(StateDisconnected)
	c.shouldDisconnect = false
	c.challengeData = make([]byte, CHALLENGE_TOKEN_BYTES)

	c.replayProtection = NewReplayProtection()
	c.connectToken = NewConnectToken()
	c.context = &Context{}
	c.packetQueue = NewPacketQueue(PACKET_QUEUE_SIZE)
	return c
}

func (c *Client) getState() ClientState {
	return c.state
}

func (c *Client) setState(newState ClientState) {
	c.state = newState
}

func (c *Client) Init() error {
	c.startTime = time.Now().Unix()
	return c.connectToken.Generate(c.config, c.sequence)
}

func (c *Client) Connect() error {
	var err error

	c.serverIndex = 0
	c.serverAddress = &c.connectToken.ServerAddrs[0]

	c.conn = NewNetcodeConn()
	c.conn.SetRecvHandler(c.onPacketData)
	if err = c.conn.Dial(c.serverAddress); err != nil {
		return err
	}

	c.context.ReadPacketKey = c.connectToken.ServerKey
	c.context.WritePacketKey = c.connectToken.ClientKey

	c.Reset()
	c.setState(StateSendingConnectionRequest)
	return nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Reset() {
	c.lastPacketRecvTime = time.Now().Unix() - 1000
	c.lastPacketSendTime = time.Now().Unix() - 1000
	c.shouldDisconnect = false
	c.shouldDisconnectState = StateDisconnected
	c.challengeData = make([]byte, CHALLENGE_TOKEN_BYTES)
	c.challengeSequence = 0
	c.replayProtection.Reset()
}

func (c *Client) resetConnectionData(newState ClientState) {
	c.sequence = 0
	c.clientIndex = 0
	c.maxClients = 0
	c.startTime = time.Now().Unix()
	c.serverIndex = 0
	c.serverAddress = nil
	c.connectToken = nil
	c.context = nil
	c.setState(newState)
	c.Reset()
	c.packetQueue.Clear()

}

func (c *Client) connectNextServer() bool {
	if c.serverIndex+1 >= len(c.connectToken.ServerAddrs) {
		return false
	}

	c.serverIndex++
	c.serverAddress = &c.connectToken.ServerAddrs[c.serverIndex]

	log.Printf("client connecting to next server %s (%d/%d)\n", c.serverAddress.String(), c.serverIndex, len(c.connectToken.ServerAddrs))
	c.setState(StateSendingConnectionRequest)
	return true
}

func (c *Client) Update(t time.Time) {
	log.Printf("Update\n")
	c.time = t.Unix()

	if err := c.send(); err != nil {
		log.Fatalf("error sending packet: %s\n", err)
	}

	state := c.getState()
	if state > StateDisconnected && state < StateConnected {
		expire := c.connectToken.ExpireTimestamp - c.connectToken.CreateTimestamp
		if c.startTime+int64(expire) <= c.time {
			c.Disconnect(StateTokenExpired, false)
			return
		}
	}

	if c.shouldDisconnect {
		log.Printf("client should disconnect -> %s\n", clientStateMap[c.shouldDisconnectState])
		if c.connectNextServer() {
			return
		}
		c.Disconnect(c.shouldDisconnectState, false)
		return
	}

	switch c.getState() {
	case StateSendingConnectionRequest:
		timeout := c.lastPacketRecvTime + int64(c.connectToken.TimeoutSeconds)
		if timeout < c.time {
			if c.connectNextServer() {
				return
			}
			c.Disconnect(StateConnectionRequestTimedOut, false)
		}
	case StateSendingConnectionResponse:
		timeout := c.lastPacketRecvTime + int64(c.connectToken.TimeoutSeconds)
		if timeout < c.time {
			if c.connectNextServer() {
				return
			}
			c.Disconnect(StateConnectionResponseTimedOut, false)
		}
	case StateConnected:
		timeout := c.lastPacketRecvTime + int64(c.connectToken.TimeoutSeconds)
		if timeout < c.time {
			c.Disconnect(StateConnectionTimedOut, false)
		}
	}
}

func (c *Client) Disconnect(reason ClientState, sendDisconnect bool) error {
	if c.getState() <= StateDisconnected {
		return nil
	}

	if sendDisconnect && c.getState() > StateDisconnected {
		for i := 0; i < NUM_DISCONNECT_PACKETS; i += 1 {
			packet := &DisconnectPacket{}
			c.sendPacket(packet)
		}
	}
	c.resetConnectionData(reason)
	return nil
}

func (c *Client) SendData(payloadData []byte) error {
	log.Printf("sending data\n")
	if c.getState() != StateConnected {
		return errors.New("client not connected, unable to send packet")
	}
	p := NewPayloadPacket(payloadData)
	return c.sendPacket(p)
}

func (c *Client) send() error {
	// check our send rate prior to bother sending
	if c.lastPacketSendTime+(1/PACKET_SEND_RATE) >= c.time {
		return nil
	}

	switch c.getState() {
	case StateSendingConnectionRequest:
		p := &RequestPacket{}
		p.VersionInfo = c.connectToken.VersionInfo
		p.ProtocolId = c.connectToken.ProtocolId
		p.ConnectTokenExpireTimestamp = c.connectToken.ExpireTimestamp
		p.ConnectTokenSequence = c.connectToken.Sequence
		p.ConnectTokenData = c.connectToken.PrivateData.Buffer()
		log.Printf("client sent connection request packet to server\n")
		return c.sendPacket(p)
	case StateSendingConnectionResponse:
		p := &ResponsePacket{}
		p.ChallengeTokenSequence = c.challengeSequence
		p.ChallengeTokenData = c.challengeData
		log.Printf("client sent connection response packet to server\n")
		return c.sendPacket(p)
	case StateConnected:
		p := &KeepAlivePacket{}
		p.ClientIndex = c.clientIndex
		p.MaxClients = c.maxClients
		log.Printf("client sent connection keep-alive packet to server\n")
		return c.sendPacket(p)
	}

	return nil
}

func (c *Client) sendPacket(packet Packet) error {
	buffer := NewBuffer(MAX_PACKET_BYTES)
	packet_bytes, err := packet.Write(buffer, c.connectToken.ProtocolId, c.sequence, c.context.WritePacketKey)
	if err != nil {
		return err
	}

	// TODO: actually check bytes written/error data
	_, err = c.conn.Write(buffer.Buf[:packet_bytes])
	return err
}

func (c *Client) RecvData() []byte {
	packet := c.packetQueue.Pop()
	p, ok := packet.(*PayloadPacket)
	if !ok {
		return nil
	}
	return p.PayloadData
}

// called asynchronously whenever a new packet of data arrives from the NetcodeConn.
func (c *Client) onPacketData(packetData []byte, from *net.UDPAddr) {
	var err error
	var size int
	var sequence uint64
	if !addressEqual(c.serverAddress, from) {
		log.Printf("unknown address sent us data")
		return
	}

	size = len(packetData)
	if len(packetData) == 0 {
		log.Printf("unable to read from socket, 0 bytes returned")
		return
	}

	allowedPackets := make([]byte, ConnectionNumPackets)
	allowedPackets[ConnectionDenied] = 1
	allowedPackets[ConnectionChallenge] = 1
	allowedPackets[ConnectionKeepAlive] = 1
	allowedPackets[ConnectionPayload] = 1
	allowedPackets[ConnectionDisconnect] = 1

	timestamp := uint64(time.Now().Unix())
	log.Printf("read %d from socket\n", len(packetData))

	packet := NewPacket(packetData)
	packetBuffer := NewBufferFromBytes(packetData)
	if err = packet.Read(packetBuffer, size, c.config.ProtocolId, timestamp, c.context.ReadPacketKey, nil, allowedPackets, c.replayProtection); err != nil {
		log.Printf("error reading packet: %s\n", err)
	}

	c.processPacket(packet, sequence)
}

func (c *Client) processPacket(packet Packet, sequence uint64) {
	log.Printf("processing packet of type: %s\n", packetTypeMap[packet.GetType()])
	state := c.getState()
	switch packet.GetType() {
	case ConnectionDenied:
		if state == StateSendingConnectionRequest || state == StateSendingConnectionResponse {
			c.shouldDisconnect = true
			c.shouldDisconnectState = StateConnectionDenied
		}
	case ConnectionChallenge:
		if state != StateSendingConnectionRequest {
			return
		}

		p, ok := packet.(*ChallengePacket)
		if !ok {
			return
		}
		c.challengeData = p.ChallengeTokenData
		c.challengeSequence = p.ChallengeTokenSequence
		c.setState(StateSendingConnectionResponse)
	case ConnectionKeepAlive:
		p, ok := packet.(*KeepAlivePacket)
		if !ok {
			return
		}

		log.Printf("client received connection keep alive packet from server\n")
		if state == StateSendingConnectionResponse {
			c.clientIndex = p.ClientIndex
			c.maxClients = p.MaxClients
			c.setState(StateConnected)
			log.Printf("client connected to server\n")
		}
	case ConnectionPayload:
		if state != StateConnected {
			return
		}
		log.Printf("got payload packet.\n")
		c.packetQueue.Push(packet)
	case ConnectionDisconnect:
		if state != StateConnected {
			return
		}
		c.shouldDisconnect = true
		c.shouldDisconnectState = StateDisconnected
	default:
		return
	}
	// always update last packet recv time for valid packets.
	c.lastPacketRecvTime = c.time
}
