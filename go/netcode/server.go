package netcode

import (
	"log"
	"net"
	"sync"
	"time"
)

type ClientManager struct {
	maxClients int

	instanceLock *sync.RWMutex
	instances    []*ClientInstance

	tokenLock *sync.RWMutex
}

func NewClientManager(maxClients int) *ClientManager {
	m := &ClientManager{}
	m.instances = make([]*ClientInstance, maxClients)
	m.maxClients = maxClients
	return m
}

func (m *ClientManager) FindByAddress(addr *net.UDPAddr) *ClientInstance {
	m.instanceLock.Lock()
	defer m.instanceLock.Unlock()
	for i := 0; i < m.maxClients; i += 1 {
		if m.instances[i] != nil && m.instances[i].address.IP.Equal(addr.IP) && m.instances[i].address.Port == addr.Port {
			return m.instances[i]
		}
	}
	return nil
}

func (m *ClientManager) FindById(id uint64) *ClientInstance {
	m.instanceLock.Lock()
	defer m.instanceLock.Unlock()
	for i := 0; i < m.maxClients; i += 1 {
		if m.instances[i] != nil && m.instances[i].clientId == id {
			return m.instances[i]
		}
	}
	return nil
}

func (m *ClientManager) FindOrAddTokenEntry() {

}

func (m *ClientManager) ClientCount() int {
	m.instanceLock.RLock()
	count := len(m.instances)
	m.instanceLock.Unlock()
	return count
}

type ClientInstance struct {
	clientId   uint64
	clientConn *NetcodeConn
	confirmed  bool
	connected  bool

	lastSendTime     int64
	lastRecvTime     int64
	userData         []byte
	replayProtection *ReplayProtection
	address          *net.UDPAddr
	connectToken     *ConnectToken
	packetQueue      *PacketQueue
}

func (c *ClientInstance) SendPacket(packet Packet) error {
	return nil
}

type Server struct {
	serverConn *NetcodeConn
	serverAddr *net.UDPAddr
	shutdownCh chan struct{}
	serverTime int64
	running    bool
	maxClients int

	clientManager  *ClientManager
	globalSequence uint64

	ignoreRequests  bool
	ignoreResponses bool
	protocolId      uint64

	privateKey        []byte
	challengeKey      []byte
	challengeSequence uint64

	recvBytes int
}

func NewServer(serverAddress *net.UDPAddr, privateKey []byte, protocolId uint64, maxClients int) *Server {
	s := &Server{}
	s.serverAddr = serverAddress
	s.protocolId = protocolId
	s.privateKey = privateKey
	s.maxClients = maxClients
	s.globalSequence = uint64(1) << 63
	s.clientManager = NewClientManager(maxClients)
	s.shutdownCh = make(chan struct{})
	return s
}

func (s *Server) SetIgnoreRequests(val bool) {
	s.ignoreRequests = val
}

func (s *Server) SetIgnoreResponses(val bool) {
	s.ignoreResponses = val
}

func (s *Server) Init() error {
	var err error

	s.challengeKey, err = GenerateKey()
	if err != nil {
		return err
	}
	s.serverConn = NewNetcodeConn()
	s.serverConn.SetRecvHandler(s.onPacketData)
	return nil
}

func (s *Server) Listen() error {
	s.running = true

	if err := s.serverConn.Listen(s.serverAddr); err != nil {
		return err
	}
	return nil
}

func (s *Server) onPacketData(packetData []byte, from *net.UDPAddr) {
	var readPacketKey []byte
	var replayProtection *ReplayProtection

	if !s.running {
		return
	}

	size := len(packetData)
	if len(packetData) == 0 {
		log.Printf("unable to read from socket, 0 bytes returned")
		return
	}

	log.Printf("net client connected")
	allowedPackets := make([]byte, ConnectionNumPackets)
	allowedPackets[ConnectionRequest] = 1
	allowedPackets[ConnectionResponse] = 1
	allowedPackets[ConnectionKeepAlive] = 1
	allowedPackets[ConnectionPayload] = 1
	allowedPackets[ConnectionDisconnect] = 1

	timestamp := uint64(time.Now().Unix())
	log.Printf("read %d from socket\n", len(packetData))

	packet := NewPacket(packetData)
	packetBuffer := NewBufferFromBytes(packetData)

	client := s.clientManager.FindByAddress(from)
	if client != nil {
		readPacketKey = client.connectToken.ClientKey
		replayProtection = client.replayProtection
	}

	if err := packet.Read(packetBuffer, size, s.protocolId, timestamp, readPacketKey, s.privateKey, allowedPackets, replayProtection); err != nil {
		log.Printf("error reading packet: %s from %s\n", err, from)
		return
	}

	s.processPacket(client, packet, from, allowedPackets, timestamp)
}

func (s *Server) processPacket(client *ClientInstance, packet Packet, addr *net.UDPAddr, allowedPackets []byte, timestamp uint64) {

	switch packet.GetType() {
	case ConnectionRequest:
		if s.ignoreRequests {
			return
		}
		log.Printf("server received connection request from %s\n", addr.String())
		s.processConnectionRequest(packet, addr)
	case ConnectionResponse:
		if s.ignoreResponses {
			return
		}
		log.Printf("server received connection response from %s\n", addr.String())
		s.processConnectionResponse(client, packet, addr)
	case ConnectionKeepAlive:
		if client == nil {
			return
		}

		client.lastRecvTime = s.serverTime

		if !client.confirmed {
			client.confirmed = true
			log.Printf("server confirmed connection to client %d:%s\n", client.clientId, client.address.String())
		}
	case ConnectionPayload:
		if client == nil {
			return
		}

		client.lastRecvTime = s.serverTime

		if !client.confirmed {
			client.confirmed = true
			log.Printf("server confirmed connection to client %d:%s\n", client.clientId, client.address.String())
		}

		client.packetQueue.Push(packet)
	case ConnectionDisconnect:
		if client == nil {
			return
		}
		log.Printf("server received disconnect packet from client %d:%s\n", client.clientId, client.address.String())
	}
}

func (s *Server) processConnectionRequest(packet Packet, addr *net.UDPAddr) {
	requestPacket, ok := packet.(*RequestPacket)
	if !ok {
		return
	}

	if len(requestPacket.Token.ServerAddrs) == 0 {
		log.Printf("server ignored connection request. server address not in connect token whitelist\n")
		return
	}

	for _, addr := range requestPacket.Token.ServerAddrs {
		if !s.serverAddr.IP.Equal(addr.IP) || s.serverAddr.Port != addr.Port {
			log.Printf("server ignored connection request. server address not in connect token whitelist\n")
			return
		}
	}

	client := s.clientManager.FindByAddress(addr)
	if client != nil {
		log.Printf("server ignored connection request. a client with this address is already connected\n")
	}

	client = s.clientManager.FindById(requestPacket.Token.ClientId)
	if client != nil {
		log.Printf("server ignored connection request. a client with this id has already been used\n")
	}

}

func (s *Server) processConnectionResponse(client *ClientInstance, packet Packet, addr *net.UDPAddr) {

}

func (s *Server) Update(time int64) error {
	s.serverTime = time

	if err := s.sendPackets(); err != nil {
		return err
	}

	if err := s.checkTimeouts(); err != nil {
		return err
	}
	return nil
}

func (s *Server) checkTimeouts() error {
	return nil
}

func (s *Server) recvPackets() error {
	return nil
}

func (s *Server) sendPackets() error {
	return nil
}

func (s *Server) sendClientPacket(packet Packet, client *ClientInstance) error {
	return nil
}

func (s *Server) disconnectClient(client *ClientInstance) error {
	return nil
}

func (s *Server) disconnectAll() error {
	return nil
}

func (s *Server) Stop() error {
	if s.running {
		close(s.shutdownCh)
		s.serverConn.Close()
		s.running = false
	}
	return nil
}

func (s *Server) connectClient() error {
	return nil
}

func (s *Server) ConnectedClientCount() int {
	return s.clientManager.ClientCount()
}
