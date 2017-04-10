package netcode

import (
	"net"
)

type ClientInstance struct {
	clientId         uint64
	clientConn       *NetcodeConn
	confirmed        bool
	connected        bool
	cryptEntry       *encryptionMapping
	lastSendTime     int64
	lastRecvTRime    int64
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

	serverTime     int64
	running        bool
	maxClients     int
	clients        []*ClientInstance
	globalSequence uint64

	flags      uint32
	protocolId uint64

	privateKey        []byte
	challengeKey      []byte
	challengeSequence uint64

	recvPacketData []byte
	recvBytes      int
}

func NewServer(config *Config, serverAddress *net.UDPAddr, maxClients int) *Server {
	s := &Server{}
	s.maxClients = maxClients
	return s
}

func (s *Server) Init() error {
	var err error

	s.challengeKey, err = GenerateKey()
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) Listen() error {
	s.running = true
	return nil
}

func (s *Server) Update(time int64) error {
	s.serverTime = time
	if err := s.recvPackets(); err != nil {
		return err
	}
	if err := s.SendPackets(); err != nil {
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

func (s *Server) processPacket() error {

}

func (s *Server) processConnection(from *net.UDPAddr, requestPacket *RequestPacket) error {
	return nil
}

func (s *Server) sendClientPacket(packet Packet, client *clientInstance) error {
	return nil
}

func (s *Server) disconnectClient(client *clientInstance) error {
	return nil
}

func (s *Server) disconnectAll() error {
	return nil
}

func (s *Server) Stop() error {
	return nil
}

func (s *Server) FindClientById(clientId int) *clientInstance {
	return nil
}

func (s *Server) FindClientByAddr(clientAddr *net.UDPAddr) *clientInstance {
	return nil
}

func (s *Server) connectClient() error {
	return nil
}

func (s *Server) ConnectedClientCount() int {
	return len(s.clients)
}
