package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/wirepair/netcode.io/go/netcode"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

var webServerAddr string
var serverAddr string
var numServers int
var startingPort int
var maxClients int

var clientId uint64
var serverAddrs []net.UDPAddr

const (
	PROTOCOL_ID          = 0x1122334455667788
	CONNECT_TOKEN_EXPIRY = 30
	TIMEOUT_SECONDS      = 1
	MAX_PACKET_BYTES     = 1220
)

// obviously you'd generate this outside of both web server and game server and store it in something
// like hashicorp vault to securely retrieve
var serverKey = []byte{0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
	0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
	0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
	0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1}

func init() {
	flag.StringVar(&webServerAddr, "webaddr", ":8880", "the web server token supplier address to bind to")
	flag.IntVar(&numServers, "numservers", 3, "number of servers to start on successive ports")
	flag.IntVar(&startingPort, "port", 40000, "starting port number, increments by 1 for number of servers")
	flag.IntVar(&maxClients, "maxclients", 8, "number of clients per server")
}

func main() {
	flag.Parse()

	// initialize server addresses for connect tokens/listening
	serverAddrs = make([]net.UDPAddr, numServers)
	for i := 0; i < numServers; i += 1 {
		addr := net.UDPAddr{IP: net.ParseIP("::1"), Port: startingPort + i}
		serverAddrs[i] = addr
	}

	// start our netcode servers

	for i := 0; i < numServers; i += 1 {
		go serveLoop(i)
	}

	// start our web server for generating and handing out connect tokens.
	http.HandleFunc("/token", serveToken)
	if err := http.ListenAndServe(webServerAddr, nil); err != nil {
		log.Fatalf("error listening: %s\n", err)
	}
}

func serveLoop(index int) {
	serv := netcode.NewServer(&serverAddrs[index], serverKey, PROTOCOL_ID, maxClients)
	if err := serv.Init(); err != nil {
		log.Fatalf("error initializing server: %s\n", err)
	}

	if err := serv.Listen(); err != nil {
		log.Fatalf("error listening: %s\n", err)
	}

	payload := make([]byte, MAX_PACKET_BYTES)
	for i := 0; i < len(payload); i += 1 {
		payload[i] = byte(i)
	}

	serverTime := float64(0.0)
	delta := float64(1.0 / 60.0)
	deltaTime := time.Duration(delta + float64(time.Second))

	count := 0
	for {
		serv.Update(serverTime)
		if serv.HasClients() > 0 {
			serv.SendPackets(serverTime)
		}

		for i := 0; i < serv.MaxClients(); i += 1 {
			for {
				responsePayload, _ := serv.RecvPayload(i)
				if len(responsePayload) == 0 {
					break
				}
				log.Printf("got payload: %d\n", len(responsePayload))
			}
		}
		time.Sleep(deltaTime)
		serverTime += deltaTime.Seconds()
		count += 1
	}
}

// this is for the web server serving tokens...
type WebToken struct {
	ClientId     uint64 `json:"client_id"`
	ConnectToken string `json:"connect_token"`
}

func serveToken(w http.ResponseWriter, r *http.Request) {
	clientId := incClientId() // safely increment the clientId

	tokenData, err := connectTokenGenerator(clientId, serverAddrs, netcode.VERSION_INFO, PROTOCOL_ID, CONNECT_TOKEN_EXPIRY, TIMEOUT_SECONDS, 0)
	if err != nil {
		fmt.Fprintf(w, "error")
		return
	}

	webToken := WebToken{ClientId: clientId, ConnectToken: base64.StdEncoding.EncodeToString(tokenData)}
	json.NewEncoder(w).Encode(webToken)
}

func connectTokenGenerator(clientId uint64, serverAddrs []net.UDPAddr, versionInfo string, protocolId uint64, tokenExpiry uint64, timeoutSeconds uint32, sequence uint64) ([]byte, error) {
	userData, err := netcode.RandomBytes(netcode.USER_DATA_BYTES)
	if err != nil {
		return nil, err
	}
	for _, x := range serverAddrs {
		log.Printf("generated: %s\n", x.String())
	}
	connectToken := netcode.NewConnectToken()
	if err := connectToken.Generate(clientId, serverAddrs, versionInfo, protocolId, tokenExpiry, timeoutSeconds, sequence, userData, serverKey); err != nil {
		return nil, err
	}

	return connectToken.Write()
}

func incClientId() uint64 {
	return atomic.AddUint64(&clientId, 1)
}
