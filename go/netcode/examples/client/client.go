package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/wirepair/netcode.io/go/netcode"
	"log"
	"net/http"
	"sync"
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

var tokenUrl string
var numClients int

func init() {
	flag.StringVar(&tokenUrl, "url", "http://localhost:8880/token", "site that gives out free tokens")
	flag.IntVar(&numClients, "num", 3, "number of clients to run concurrently")
}

func main() {
	flag.Parse()
	wg := &sync.WaitGroup{}

	wg.Add(numClients)
	for i := 0; i < numClients; i += 1 {
		token := getConnectToken()
		go clientLoop(wg, token)
	}
	wg.Wait()
}

func clientLoop(wg *sync.WaitGroup, connectToken *netcode.ConnectToken) {

	clientTime := float64(0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta + float64(time.Second))

	c := netcode.NewClient(connectToken)

	if err := c.Connect(); err != nil {
		log.Fatalf("error connecting: %s\n", err)
	}

	packetData := make([]byte, 1200)
	count := 0

	// fake game loop
	for {

		if clientTime > 4.0 {
			log.Printf("client exiting recv'd %d payloads...", count)
			wg.Done()
		}

		c.Update(clientTime)
		if c.GetState() == netcode.StateConnected {
			c.SendData(packetData)
		}

		for {
			if payload := c.RecvData(); payload == nil {
				break
			} else {
				log.Printf("recv'd payload: of %d bytes\n", len(payload))
				count++
				return
			}
		}
		time.Sleep(deltaTime)
		clientTime += deltaTime.Seconds()
	}

}

// this is from the web server serving tokens...
type WebToken struct {
	ClientId     uint64 `json:"client_id"`
	ConnectToken string `json:"connect_token"`
}

func getConnectToken() *netcode.ConnectToken {

	resp, err := http.Get(tokenUrl)
	if err != nil {
		log.Fatalf("error getting token from %s: %s\n", tokenUrl, err)
	}
	defer resp.Body.Close()
	webToken := &WebToken{}

	if err := json.NewDecoder(resp.Body).Decode(webToken); err != nil {
		log.Fatalf("error decoding web token: %s\n", err)
	}
	log.Printf("Got token for clientId: %d\n", webToken.ClientId)

	tokenBuffer, err := base64.StdEncoding.DecodeString(webToken.ConnectToken)
	if err != nil {
		log.Fatalf("error decoding connect token: %s\n", err)
	}

	token, err := netcode.ReadConnectToken(tokenBuffer)
	if err != nil {
		log.Fatalf("error reading connect token: %s\n", err)
	}
	return token
}
