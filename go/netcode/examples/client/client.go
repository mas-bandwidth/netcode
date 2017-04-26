package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/wirepair/netcode.io/go/netcode"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var totalPayloadCount uint64
var totalSendCount uint64
var totalTickCount uint64

var tokenUrl string
var numClients int

func init() {
	flag.StringVar(&tokenUrl, "url", "http://localhost:8880/token", "site that gives out free tokens")
	flag.IntVar(&numClients, "num", 256, "number of clients to run concurrently")
}

func main() {
	flag.Parse()
	wg := &sync.WaitGroup{}

	for i := 0; i < numClients; i += 1 {
		wg.Add(1)
		token, id := getConnectToken()
		go clientLoop(wg, id, token)
	}
	wg.Wait()
	log.Printf("%d clients sent %d packets, recv'd %d payloads in %d ticks\n", numClients, totalSendCount, totalPayloadCount, totalTickCount)
}

func clientLoop(wg *sync.WaitGroup, id uint64, connectToken *netcode.ConnectToken) {

	clientTime := float64(0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta * float64(time.Second))

	c := netcode.NewClient(connectToken)
	c.SetId(id)

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

	// randomize start time so we don't flood ourselves/server
	time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)

	// fake game loop
	for {

		if clientTime > 6.0 {
			log.Printf("client[%d] exiting recv'd %d payloads... from %d ticks", id, count, ticks)
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
				count++
			}
		}
		time.Sleep(deltaTime)
		clientTime += deltaTime.Seconds()
		ticks++
	}

}

// this is from the web server serving tokens...
type WebToken struct {
	ClientId     uint64 `json:"client_id"`
	ConnectToken string `json:"connect_token"`
}

func getConnectToken() (*netcode.ConnectToken, uint64) {

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
	return token, webToken.ClientId
}
