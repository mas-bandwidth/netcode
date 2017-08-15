package netcode

import (
	"fmt"
	"net"
	"testing"
	"time"
)

const testClientCommsEnabled = false // this is for testing servers independently

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

	connectToken := testGenerateConnectToken(servers, TEST_PRIVATE_KEY, t)

	c := NewClient(connectToken)
	if err := c.Connect(); err != nil {
		t.Fatalf("error connecting: %s\n", err)
	}

	if c.conn.RemoteAddr().String() != "127.0.0.1:40000" {
		t.Fatalf("remote address was incorrect.")
	}

}

func TestClientCommunications(t *testing.T) {
	if !testClientCommsEnabled {
		return
	}
	server := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	connectToken := testGenerateConnectToken(servers, TEST_PRIVATE_KEY, t)

	clientTime := float64(0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta * float64(time.Second))

	c := NewClient(connectToken)

	if err := c.Connect(); err != nil {
		t.Fatalf("error connecting: %s\n", err)
	}

	packetData := make([]byte, MAX_PAYLOAD_BYTES)
	for i := 0; i < MAX_PAYLOAD_BYTES; i += 1 {
		packetData[i] = byte(i)
	}
	count := 0

	// fake game loop
	for {
		if count == 20 {
			c.Close()
			t.Fatalf("never recv'd a payload packet")
			return
		}
		c.Update(clientTime)
		if c.GetState() == StateConnected {
			c.SendData(packetData)
		}

		for {
			if payload, seq := c.RecvData(); payload == nil {
				break
			} else {
				fmt.Printf("seq: %d recv'd payload: of %d bytes\n", seq, len(payload))
				return
			}
		}
		time.Sleep(deltaTime)
		clientTime += deltaTime.Seconds()
		count++
	}
}
