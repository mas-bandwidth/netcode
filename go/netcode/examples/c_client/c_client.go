package main

import (
	"flag"
	"github.com/wirepair/netcode.io/go/netcode"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
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

var numClients int

var totalPayloadCount uint64
var totalSendCount uint64
var totalTickCount uint64

func init() {
	flag.IntVar(&numClients, "num", 3, "number of clients to run concurrently")
}

func main() {
	flag.Parse()
	wg := &sync.WaitGroup{}

	for i := 0; i < numClients; i += 1 {
		wg.Add(1)
		token := getConnectToken(uint64(i))
		go clientLoop(wg, token)
	}
	wg.Wait()
	log.Printf("%d clients sent %d packets, recv'd %d payloads in %d ticks\n", numClients, totalSendCount, totalPayloadCount, totalTickCount)
}

func clientLoop(wg *sync.WaitGroup, connectToken *netcode.ConnectToken) {

	clientTime := float64(0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta * float64(time.Second))

	c := netcode.NewClient(connectToken)

	if err := c.Connect(); err != nil {
		log.Fatalf("error connecting: %s\n", err)
	}

	log.Printf("client connected, local address: %s\n", c.LocalAddr())
	packetData := make([]byte, netcode.MAX_PAYLOAD_BYTES)
	for i := 0; i < len(packetData); i += 1 {
		packetData[i] = byte(i)
	}

	count := 0
	sendCount := 0
	ticks := 0

	time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
	// fake game loop
	for {

		if clientTime > 6.0 {
			log.Printf("client exiting recv'd %d payloads...", count)
			atomic.AddUint64(&totalTickCount, uint64(ticks))
			atomic.AddUint64(&totalPayloadCount, uint64(count))
			atomic.AddUint64(&totalSendCount, uint64(sendCount))
			wg.Done()
			return
		}

		c.Update(clientTime)
		if c.GetState() == netcode.StateConnected {
			c.SendData(packetData)
			sendCount++
		}

		for {
			if payload, _ := c.RecvData(); payload == nil {
				break
			} else {
				//log.Printf("recv'd payload: of %d bytes with sequence: %d\n", len(payload), seq)
				count++
			}
		}
		time.Sleep(deltaTime)
		clientTime += deltaTime.Seconds()
		ticks++
	}

}

func getConnectToken(clientId uint64) *netcode.ConnectToken {
	server := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	servers := make([]net.UDPAddr, 1)
	servers[0] = server

	privateKey := PRIVATE_KEY

	userData, err := netcode.RandomBytes(netcode.USER_DATA_BYTES)
	if err != nil {
		log.Fatalf("error generating userdata bytes: %s\n", err)
	}

	connectToken := netcode.NewConnectToken()
	// generate will write & encrypt the ConnectTokenPrivate
	if err := connectToken.Generate(clientId, servers, netcode.VERSION_INFO, PROTOCOL_ID, CONNECT_TOKEN_EXPIRY, TIMEOUT_SECONDS, SEQUENCE_START, userData, privateKey); err != nil {
		log.Fatalf("error generating token: %s\n", err)
	}
	return connectToken
}
