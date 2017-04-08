package netcode

import (
	"fmt"
	"net"
	"testing"
	"time"
)

const (
	TEST_PROTOCOL_ID          = 0x1122334455667788
	TEST_CONNECT_TOKEN_EXPIRY = 30
	TEST_SERVER_PORT          = 40000
	TEST_CLIENT_ID            = 0x1
	TEST_SEQUENCE_START       = 1000
	TEST_TIMEOUT_SECONDS      = 1
)

var TEST_PRIVATE_KEY = []byte{0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
	0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
	0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
	0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1}

func TestClientInit(t *testing.T) {
	server := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	config := NewConfig(servers, TEST_TIMEOUT_SECONDS, TEST_CONNECT_TOKEN_EXPIRY, TEST_CLIENT_ID, TEST_PROTOCOL_ID, TEST_PRIVATE_KEY)

	c := NewClient(config)
	if err := c.Init(); err != nil {
		t.Fatalf("error initializing client: %s\n", err)
	}

	if err := c.Connect(); err != nil {
		t.Fatalf("error connecting: %s\n", err)
	}

	if c.conn.RemoteAddr().String() != "127.0.0.1:40000" {
		t.Fatalf("remote address was incorrect.")
	}

}

func TestClientCommunications(t *testing.T) {
	server := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	config := NewConfig(servers, TEST_TIMEOUT_SECONDS, TEST_CONNECT_TOKEN_EXPIRY, TEST_CLIENT_ID, TEST_PROTOCOL_ID, TEST_PRIVATE_KEY)

	deltaTime := time.Duration(time.Second * 1.0 / 60.0)

	c := NewClient(config)
	if err := c.Init(); err != nil {
		t.Fatalf("error initializing client: %s\n", err)
	}

	if err := c.Connect(); err != nil {
		t.Fatalf("error connecting: %s\n", err)
	}

	packetData := make([]byte, 1200)
	for {
		timestamp := time.Now()
		c.Update(timestamp)
		fmt.Println("sending update")
		if c.state == StateConnected {
			c.SendData(packetData)
			fmt.Println("sent data")
		}

		for {
			fmt.Println("recv'ing data")
			if payload := c.RecvData(); payload == nil {
				break
			} else {
				fmt.Printf("recv'd payload: %#v\n", payload)
			}
		}
		time.Sleep(deltaTime)
	}
}
