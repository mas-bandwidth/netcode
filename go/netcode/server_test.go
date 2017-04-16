package netcode

import (
	"net"
	"testing"
	"time"
)

const testEnableServerCommsListen = true

func TestServerListen(t *testing.T) {
	if !testEnableServerCommsListen {
		return
	}
	maxClients := 32
	addr := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	serv := NewServer(&addr, TEST_PRIVATE_KEY, TEST_PROTOCOL_ID, maxClients)
	if err := serv.Init(); err != nil {
		t.Fatalf("error initializing server: %s\n", err)
	}

	if err := serv.Listen(); err != nil {
		t.Fatalf("error listening: %s\n", err)
	}

	payload := make([]byte, MAX_PACKET_BYTES)
	for i := 0; i < len(payload); i += 1 {
		payload[i] = byte(i)
	}

	serverTime := float64(0.0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta + float64(time.Second))
	count := 0
	payloadCount := 0
	for {
		serv.Update(serverTime)
		if serv.HasClients() > 0 {
			serv.SendPackets(serverTime)
		}

		if count > 0 && payloadCount > 1000 {
			return
		}

		for i := 0; i < serv.MaxClients(); i += 1 {
			for {
				responsePayload, _ := serv.RecvPayload(i)
				if len(responsePayload) == 0 {
					break
				}
				payloadCount++
				t.Logf("got payload: %d\n", len(responsePayload))
			}
		}
		time.Sleep(deltaTime)
		serverTime += deltaTime.Seconds()
		count += 1
	}
}
