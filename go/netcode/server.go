package netcode

import (
	"log"
	"net"
	"time"
)

type Server struct {
	serverConn       *NetcodeConn
	serverAddr       *net.UDPAddr
	shutdownCh       chan struct{}
	serverTime       int64
	running          bool
	maxClients       int
	connectedClients int

	clientManager  *ClientManager
	globalSequence uint64

	ignoreRequests  bool
	ignoreResponses bool
	allowedPackets  []byte
	protocolId      uint64

	privateKey   []byte
	challengeKey []byte

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

	// set allowed packets for this server
	s.allowedPackets = make([]byte, ConnectionNumPackets)
	s.allowedPackets[ConnectionRequest] = 1
	s.allowedPackets[ConnectionResponse] = 1
	s.allowedPackets[ConnectionKeepAlive] = 1
	s.allowedPackets[ConnectionPayload] = 1
	s.allowedPackets[ConnectionDisconnect] = 1
	s.allowedPackets[ConnectionChallenge] = 1
	return s
}

func (s *Server) SetAllowedPackets(allowedPackets []byte) {
	s.allowedPackets = allowedPackets
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
	s.serverConn.SetRecvHandler(s.OnPacketData)
	return nil
}

func (s *Server) Listen() error {
	s.running = true

	if err := s.serverConn.Listen(s.serverAddr); err != nil {
		return err
	}
	return nil
}

func (s *Server) OnPacketData(packetData []byte, addr *net.UDPAddr) {
	var readPacketKey []byte
	var replayProtection *ReplayProtection

	if !s.running {
		return
	}

	encryptionIndex := -1

	clientIndex := s.clientManager.FindClientIndexByAddress(addr)
	if clientIndex != -1 {
		encryptionIndex = s.clientManager.FindEncryptionIndexByClientIndex(clientIndex)
	} else {
		encryptionIndex = s.clientManager.FindEncryptionEntryIndex(addr, s.serverTime)
	}

	size := len(packetData)
	if len(packetData) == 0 {
		log.Printf("unable to read from socket, 0 bytes returned")
		return
	}

	log.Printf("net client connected")

	timestamp := uint64(time.Now().Unix())
	log.Printf("read %d from socket\n", len(packetData))

	packet := NewPacket(packetData)
	packetBuffer := NewBufferFromBytes(packetData)

	if clientIndex != -1 {
		client := s.clientManager.instances[clientIndex]
		readPacketKey = client.connectToken.ClientKey
		replayProtection = client.replayProtection
	}

	if err := packet.Read(packetBuffer, size, s.protocolId, timestamp, readPacketKey, s.privateKey, s.allowedPackets, replayProtection); err != nil {
		log.Printf("error reading packet: %s from %s\n", err, addr)
		return
	}

	s.processPacket(clientIndex, encryptionIndex, packet, addr)
}

func (s *Server) processPacket(clientIndex, encryptionIndex int, packet Packet, addr *net.UDPAddr) {
	log.Printf("processing %s packet\n", packetTypeMap[packet.GetType()])
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
		s.processConnectionResponse(clientIndex, encryptionIndex, packet, addr)
	case ConnectionKeepAlive:
		if clientIndex == -1 {
			return
		}
		client := s.clientManager.instances[clientIndex]
		client.lastRecvTime = s.serverTime

		if !client.confirmed {
			client.confirmed = true
			log.Printf("server confirmed connection to client %d:%s\n", client.clientId, client.address.String())
		}
	case ConnectionPayload:
		if clientIndex == -1 {
			return
		}
		client := s.clientManager.instances[clientIndex]
		client.lastRecvTime = s.serverTime

		if !client.confirmed {
			client.confirmed = true
			log.Printf("server confirmed connection to client %d:%s\n", client.clientId, client.address.String())
		}

		client.packetQueue.Push(packet)
	case ConnectionDisconnect:
		if clientIndex == -1 {
			return
		}
		client := s.clientManager.instances[clientIndex]
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
		if !addressEqual(s.serverAddr, &addr) {
			log.Printf("server ignored connection request. server address not in connect token whitelist\n")
			return
		}
	}

	clientIndex := s.clientManager.FindClientIndexByAddress(addr)
	if clientIndex != -1 {
		log.Printf("server ignored connection request. a client with this address is already connected\n")
	}

	clientIndex = s.clientManager.FindClientIndexById(requestPacket.Token.ClientId)
	if clientIndex != -1 {
		log.Printf("server ignored connection request. a client with this id has already been used\n")
	}

	if !s.clientManager.FindOrAddTokenEntry(requestPacket.Token.Mac(), addr, s.serverTime) {
		log.Printf("server ignored connection request. connect token has already been used\n")
	}

	if s.clientManager.ConnectedClientCount() == s.maxClients {
		log.Printf("server denied connection request. server is full\n")
		s.sendDeniedPacket(requestPacket.Token.ServerKey, addr)
		return
	}

	if !s.clientManager.AddEncryptionMapping(requestPacket.Token, addr, s.serverTime, s.serverTime+TIMEOUT_SECONDS) {
		log.Printf("server ignored connection request. failed to add encryption mapping\n")
		return
	}

	s.sendChallengePacket(requestPacket, addr)
}

func (s *Server) sendChallengePacket(requestPacket *RequestPacket, addr *net.UDPAddr) {
	var bytesWritten int
	var err error

	challenge := NewChallengeToken(requestPacket.Token.ClientId)
	challengeBuf := challenge.Write(requestPacket.Token.UserData)
	challengeSequence := s.challengeSequence

	s.challengeSequence++

	if err := EncryptChallengeToken(&challengeBuf, challengeSequence, s.challengeKey); err != nil {
		log.Printf("server ignored connection request. failed to encrypt challenge token\n")
		return
	}

	challengePacket := &ChallengePacket{}
	challengePacket.ChallengeTokenData = challengeBuf
	challengePacket.ChallengeTokenSequence = challengeSequence

	buffer := NewBuffer(MAX_PACKET_BYTES)
	if bytesWritten, err = challengePacket.Write(buffer, s.protocolId, s.globalSequence, requestPacket.Token.ServerKey); err != nil {
		log.Printf("server error while writing challenge packet\n")
		return
	}
	s.globalSequence++

	log.Printf("server sent connection challenge packet to: %s using key: %#v\n", addr.String(), requestPacket.Token.ServerKey)
	s.sendGlobalPacket(buffer.Buf[:bytesWritten], addr)
}

func (s *Server) sendGlobalPacket(packetBuffer []byte, addr *net.UDPAddr) {
	if _, err := s.serverConn.WriteTo(packetBuffer, addr); err != nil {
		log.Printf("error sending packet to %s\n", addr.String())
	}
}

func (s *Server) processConnectionResponse(clientIndex, encryptionIndex int, packet Packet, addr *net.UDPAddr) {
	var err error
	var tokenBuffer []byte
	var challengeToken *ChallengeToken

	responsePacket, ok := packet.(*ResponsePacket)
	if !ok {
		return
	}

	if tokenBuffer, err = DecryptChallengeToken(responsePacket.ChallengeTokenData, responsePacket.ChallengeTokenSequence, s.challengeKey); err != nil {
		log.Printf("failed to decrypt challenge token: %s\n", err)
		return
	}

	if challengeToken, err = ReadChallengeToken(tokenBuffer); err != nil {
		log.Printf("failed to read challenge token: %s\n", err)
		return
	}

	sendKey := s.clientManager.GetEncryptionEntrySendKey(encryptionIndex)
	if sendKey == nil {
		log.Printf("server ignored connection response. no packet send key\n")
	}

	if s.clientManager.FindClientIndexByAddress(addr) != -1 {
		log.Printf("server ignored connection response. a client with this address is already connected")
	}

	if s.clientManager.FindClientIndexById(challengeToken.ClientId) != -1 {
		log.Printf("server ignored connection response. a client with this id is already connected")
	}

	if s.clientManager.ConnectedClientCount() == s.maxClients {
		log.Printf("server denied connection response. server is full\n")
		s.sendDeniedPacket(sendKey, addr)
		return
	}

	clientIndex = s.clientManager.FindFreeClientIndex()
	if clientIndex == -1 {
		log.Printf("failure to find free client index\n")
		return
	}
	s.connectClient(clientIndex, encryptionIndex, challengeToken, addr)
	return

}

func (s *Server) sendDeniedPacket(sendKey []byte, addr *net.UDPAddr) {
	var bytesWritten int
	var err error

	deniedPacket := &DeniedPacket{}
	packetBuffer := NewBuffer(MAX_PACKET_BYTES)
	if bytesWritten, err = deniedPacket.Write(packetBuffer, s.protocolId, s.globalSequence, sendKey); err != nil {
		log.Printf("error creating denied packet: %s\n", err)
		return
	}
	s.globalSequence++
	s.sendGlobalPacket(packetBuffer.Buf[:bytesWritten], addr)
}

func (s *Server) connectClient(clientIndex, encryptionIndex int, challengeToken *ChallengeToken, addr *net.UDPAddr) {

	if s.clientManager.ConnectedClientCount() > s.maxClients {
		log.Printf("maxium number of clients reached")
		return
	}

	s.clientManager.SetEncryptionEntryExpiration(encryptionIndex, -1)
	client := s.clientManager.instances[clientIndex]
	client.serverConn = s.serverConn
	client.clientIndex = clientIndex
	client.connected = true
	client.clientId = challengeToken.ClientId
	client.protocolId = s.protocolId
	client.sequence = 0
	client.address = addr
	client.lastSendTime = s.serverTime
	client.lastRecvTime = s.serverTime
	copy(client.userData, challengeToken.UserData.Bytes())
	log.Printf("server accepted client %d from %s in slot: %d\n", client.clientId, addr.String(), clientIndex)
	s.sendKeepAlive(client, clientIndex)
}

func (s *Server) sendKeepAlive(client *ClientInstance, clientIndex int) {
	packet := &KeepAlivePacket{}
	packet.ClientIndex = uint32(clientIndex)
	packet.MaxClients = uint32(s.maxClients)

	if !s.clientManager.TouchEncryptionEntry(client.encryptionIndex, client.address, s.serverTime) {
		log.Printf("error: encryption mapping is out of date for client %d\n", clientIndex)
		return
	}

	writePacketKey := s.clientManager.GetEncryptionEntrySendKey(client.encryptionIndex)
	if writePacketKey == nil {
		log.Printf("error: unable to retrieve encryption key for client: %d\n", clientIndex)
		return
	}

	if err := client.SendPacket(packet, writePacketKey, s.serverTime); err != nil {
		log.Printf("%s\n", err)
	}
}

func (s *Server) SendPackets(serverTime int64) {
	s.clientManager.SendPackets(serverTime)
	return
}

func (s *Server) Update(time int64) {
	if !s.running {
		return
	}

	s.serverTime = time
	s.clientManager.SendPackets(s.serverTime)
	s.clientManager.CheckTimeouts(s.serverTime)
}

func (s *Server) MaxClients() int {
	return s.maxClients
}

func (s *Server) HasClients() int {
	return s.clientManager.ConnectedClientCount()
}

func (s *Server) Stop() error {
	if !s.running {
		return nil
	}
	s.clientManager.disconnectClients(s.serverTime)

	s.running = false
	s.maxClients = 0
	s.globalSequence = 0
	s.challengeSequence = 0
	s.challengeKey = make([]byte, KEY_BYTES)
	s.clientManager.resetCryptoEntries()
	s.clientManager.resetTokenEntries()
	close(s.shutdownCh)
	s.running = false
	s.serverConn.Close()

	return nil
}

func (s *Server) RecvPayload(clientIndex int) ([]byte, uint64) {
	packet := s.clientManager.instances[clientIndex].packetQueue.Pop()
	if packet == nil {
		return []byte{}, 0
	}
	p, ok := packet.(*PayloadPacket)
	if !ok {
		log.Printf("not a payload packet")
		return []byte{}, 0
	}
	return p.PayloadData, p.sequence
}

func addressEqual(addr1, addr2 *net.UDPAddr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	return addr1.IP.Equal(addr2.IP) && addr1.Port == addr2.Port
}
