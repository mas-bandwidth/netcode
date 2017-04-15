package main

import (
	"github.com/wirepair/netcode.io/go/netcode"
	"log"
	"net"
	"time"
)

const (
	PROTOCOL_ID          = 0x1122334455667788
	CONNECT_TOKEN_EXPIRY = 30
	SERVER_PORT          = 40000
	CLIENT_ID            = 0x1
	SEQUENCE_START       = 1000
	TIMEOUT_SECONDS      = 1
)

var PRIVATE_KEY = []byte{0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
	0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
	0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
	0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1}

func main() {

	server := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	connectToken := testGenerateConnectToken(servers, PRIVATE_KEY)
	deltaTime := time.Duration(time.Second * 1.0 / 60.0)

	c := netcode.NewClient(connectToken)

	if err := c.Connect(); err != nil {
		log.Fatalf("error connecting: %s\n", err)
	}

	packetData := make([]byte, 1200)
	count := 0
	timestamp := int64(0)
	// fake game loop
	for {
		if count == 10 {
			log.Fatalf("error communicating with server")
		}
		c.Update(timestamp)
		log.Println("sending update")
		if c.GetState() == netcode.StateConnected {
			c.SendData(packetData)
			log.Println("sent data")
		}

		for {
			log.Println("recv'ing data")
			if payload := c.RecvData(); payload == nil {
				break
			} else {
				log.Printf("recv'd payload: of %d bytes\n", len(payload))
				return
			}
		}
		time.Sleep(deltaTime)
		timestamp += int64(deltaTime.Seconds())
		count++
	}

}

func testGenerateConnectToken(servers []net.UDPAddr, privateKey []byte) *netcode.ConnectToken {
	if privateKey == nil {
		privateKey = PRIVATE_KEY
	}

	userData, err := netcode.RandomBytes(netcode.USER_DATA_BYTES)
	if err != nil {
		log.Fatalf("error generating userdata bytes: %s\n", err)
	}

	connectToken := netcode.NewConnectToken()
	// generate will write & encrypt the ConnectTokenPrivate
	if err := connectToken.Generate(CLIENT_ID, servers, netcode.VERSION_INFO, PROTOCOL_ID, CONNECT_TOKEN_EXPIRY, TIMEOUT_SECONDS, SEQUENCE_START, userData, privateKey); err != nil {
		log.Fatalf("error generating token: %s\n", err)
	}
	return connectToken
}
