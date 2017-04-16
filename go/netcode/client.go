package netcode

import (
	"errors"
	"log"
	"net"
	"time"
)

const CLIENT_MAX_RECEIVE_PACKETS = 64
const SERVER_MAX_RECEIVE_PACKETS = (64 * MAX_CLIENTS)
const PACKET_SEND_RATE = 10.0
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
	id           uint64
	connectToken *ConnectToken

	time                  float64
	startTime             float64
	lastPacketSendTime    float64
	lastPacketRecvTime    float64
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
	context          *Context
	replayProtection *ReplayProtection
	conn             *NetcodeConn
	packetQueue      *PacketQueue
	allowedPackets   []byte
}

func NewClient(connectToken *ConnectToken) *Client {
	c := &Client{connectToken: connectToken}
	c.lastPacketRecvTime = -1
	c.lastPacketSendTime = -1
	c.setState(StateDisconnected)
	c.shouldDisconnect = false
	c.challengeData = make([]byte, CHALLENGE_TOKEN_BYTES)

	c.context = &Context{}
	c.packetQueue = NewPacketQueue(PACKET_QUEUE_SIZE)
	c.replayProtection = NewReplayProtection()

	c.allowedPackets = make([]byte, ConnectionNumPackets)
	c.allowedPackets[ConnectionDenied] = 1
	c.allowedPackets[ConnectionChallenge] = 1
	c.allowedPackets[ConnectionKeepAlive] = 1
	c.allowedPackets[ConnectionPayload] = 1
	c.allowedPackets[ConnectionDisconnect] = 1
	return c
}

func (c *Client) GetState() ClientState {
	return c.state
}

func (c *Client) setState(newState ClientState) {
	c.state = newState
}

func (c *Client) Connect() error {
	var err error

	c.startTime = 0
	if c.serverIndex > len(c.connectToken.ServerAddrs) {
		return errors.New("invalid server address, exceeded # of servers")
	}

	c.serverAddress = &c.connectToken.ServerAddrs[c.serverIndex]

	c.conn = NewNetcodeConn()
	c.conn.SetRecvHandler(c.onPacketData)
	if err = c.conn.Dial(c.serverAddress); err != nil {
		return err
	}

	c.context.ReadPacketKey = c.connectToken.ServerKey
	c.context.WritePacketKey = c.connectToken.ClientKey

	c.setState(StateSendingConnectionRequest)
	return nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Reset() {
	c.lastPacketSendTime = c.time - 1
	c.lastPacketRecvTime = c.time
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
	c.startTime = 0
	c.serverIndex = 0
	c.serverAddress = nil
	c.connectToken = nil
	c.context = nil
	c.setState(newState)
	c.Reset()
	c.packetQueue.Clear()
}

func (c *Client) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
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

func (c *Client) Update(t float64) {
	c.time = t

	if err := c.send(); err != nil {
		log.Fatalf("error sending packet: %s\n", err)
	}

	state := c.GetState()
	if state > StateDisconnected && state < StateConnected {
		expire := c.connectToken.ExpireTimestamp - c.connectToken.CreateTimestamp
		if c.startTime+float64(expire) <= c.time {
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

	switch c.GetState() {
	case StateSendingConnectionRequest:
		timeout := c.lastPacketRecvTime + float64(c.connectToken.TimeoutSeconds)
		if timeout < c.time {
			log.Printf("connection request timed out.")
			if c.connectNextServer() {
				return
			}
			c.Disconnect(StateConnectionRequestTimedOut, false)
		}
	case StateSendingConnectionResponse:
		timeout := c.lastPacketRecvTime + float64(c.connectToken.TimeoutSeconds)
		if timeout < c.time {
			if c.connectNextServer() {
				return
			}
			c.Disconnect(StateConnectionResponseTimedOut, false)
		}
	case StateConnected:
		timeout := c.lastPacketRecvTime + float64(c.connectToken.TimeoutSeconds)
		if timeout < c.time {
			c.Disconnect(StateConnectionTimedOut, false)
		}
	}
}

func (c *Client) Disconnect(reason ClientState, sendDisconnect bool) error {
	log.Printf("disconnected: %s\n", clientStateMap[reason])
	if c.GetState() <= StateDisconnected {
		return nil
	}

	if sendDisconnect && c.GetState() > StateDisconnected {
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
	if c.GetState() != StateConnected {
		return errors.New("client not connected, unable to send packet")
	}
	p := NewPayloadPacket(payloadData)
	return c.sendPacket(p)
}

func (c *Client) send() error {
	// check our send rate prior to bother sending
	if c.lastPacketSendTime+float64(1.0/PACKET_SEND_RATE) >= c.time {
		return nil
	}

	switch c.GetState() {
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
		p.ClientIndex = 0
		p.MaxClients = 0
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

	_, err = c.conn.Write(buffer.Buf[:packet_bytes])
	if err != nil {
		log.Printf("error writing packet %s to server: %s\n", packetTypeMap[packet.GetType()], err)
	}
	c.lastPacketSendTime = c.time
	c.sequence++
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

	timestamp := uint64(time.Now().Unix())
	log.Printf("read %d from socket\n", len(packetData))

	packet := NewPacket(packetData)
	packetBuffer := NewBufferFromBytes(packetData)
	if err = packet.Read(packetBuffer, size, c.connectToken.ProtocolId, timestamp, c.context.ReadPacketKey, nil, c.allowedPackets, c.replayProtection); err != nil {
		log.Printf("error reading packet: %s\n", err)
	}

	c.processPacket(packet, sequence)
}

func (c *Client) processPacket(packet Packet, sequence uint64) {
	log.Printf("processing packet of type: %s\n", packetTypeMap[packet.GetType()])
	state := c.GetState()
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
