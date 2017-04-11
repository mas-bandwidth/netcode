package netcode

import (
	"net"
	"testing"
)

func TestServerListen(t *testing.T) {
	addr := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	serv := NewServer(&addr, TEST_PRIVATE_KEY, TEST_PROTOCOL_ID, 32)
	if err := serv.Init(); err != nil {
		t.Fatalf("error initializing server: %s\n", err)
	}

	if err := serv.Listen(); err != nil {
		t.Fatalf("error listening: %s\n", err)
	}

}
