package netcode

import (
	"log"
	"net"
)

type ClientInstance struct {
	clientId   uint64
	clientConn *NetcodeConn
	confirmed  bool
	connected  bool
	//cryptEntry       *encryptionMapping
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

type ConnectionHandler func(conn *NetcodeConn)

type Server struct {
	serverConn          *NetcodeConn
	serverAddr          *net.UDPAddr
	shutdownCh          chan struct{}
	connectionHandlerFn ConnectionHandler
	serverTime          int64
	running             bool
	maxClients          int
	clients             []*ClientInstance
	globalSequence      uint64

	flags      uint32
	protocolId uint64

	privateKey        []byte
	challengeKey      []byte
	challengeSequence uint64

	recvPacketData []byte
	recvBytes      int
}

func NewServer(serverAddress *net.UDPAddr, privateKey []byte, protocolId uint64, maxClients int) *Server {
	s := &Server{}
	s.serverAddr = serverAddress
	s.protocolId = protocolId
	s.privateKey = privateKey
	s.maxClients = maxClients

	s.shutdownCh = make(chan struct{})
	s.connectionHandlerFn = s.defaultConnectionHandler
	return s
}

func (s *Server) SetConnectionHandler(handler ConnectionHandler) {
	s.connectionHandlerFn = handler
}

func (s *Server) Init() error {
	var err error

	s.challengeKey, err = GenerateKey()
	if err != nil {
		return err
	}
	s.serverConn = NewNetcodeConn(s.serverAddr)
	return nil
}

func (s *Server) Listen() error {
	s.running = true

	if err := s.serverConn.Listen(); err != nil {
		return err
	}

	go s.listenLoop()
	return nil
}

func (s *Server) listenLoop() {
	/*
		for {
			conn, err := s.serverConn.Accept()
			if err != nil {
				return
			}

			select {
			case <-s.shutdownCh:
				return
			default:
				go s.connectionHandlerFn(conn)
			}
		}
	*/
}

func (s *Server) defaultConnectionHandler(conn *NetcodeConn) {
	log.Printf("net client connected")
	s.Stop()
}

func (s *Server) Update(time int64) error {
	s.serverTime = time

	if err := s.recvPackets(); err != nil {
		return err
	}

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

func (s *Server) processPacket() error {
	return nil
}

func (s *Server) processConnection(from *net.UDPAddr, requestPacket *RequestPacket) error {
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
		s.running = false
	}
	return nil
}

func (s *Server) FindClientById(clientId int) *ClientInstance {
	return nil
}

func (s *Server) FindClientByAddr(clientAddr *net.UDPAddr) *ClientInstance {
	return nil
}

func (s *Server) connectClient() error {
	return nil
}

func (s *Server) ConnectedClientCount() int {
	return len(s.clients)
}
