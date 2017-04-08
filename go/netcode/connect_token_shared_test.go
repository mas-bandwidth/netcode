package netcode

import (
	"bytes"
	"net"
	"testing"
)

func TestReadWriteShared(t *testing.T) {
	var err error
	var clientKey []byte
	var serverKey []byte
	clientKey, err = RandomBytes(KEY_BYTES)
	if err != nil {
		t.Fatalf("error generating client key")
	}

	serverKey, err = RandomBytes(KEY_BYTES)
	if err != nil {
		t.Fatalf("error generating server key")
	}

	server := net.UDPAddr{IP: net.ParseIP("::1"), Port: 40000}
	t.Logf("%#v\n", server.IP)
	data := &sharedTokenData{}
	data.ServerAddrs = make([]net.UDPAddr, 1)
	data.ServerAddrs[0] = server
	data.ClientKey = clientKey
	data.ServerKey = serverKey

	buffer := NewBuffer(CONNECT_TOKEN_BYTES)
	if err := data.WriteShared(buffer); err != nil {
		t.Fatalf("error writing shared buffer: %s\n", err)
	}

	// reset
	buffer.Reset()
	outData := &sharedTokenData{}

	outData.ReadShared(buffer)

	if bytes.Compare(clientKey, outData.ClientKey) != 0 {
		t.Fatalf("client key did not match")
	}

	if bytes.Compare(serverKey, outData.ServerKey) != 0 {
		t.Fatalf("server key did not match")
	}

	if !outData.ServerAddrs[0].IP.Equal(server.IP) {
		t.Fatalf("server address did not match")
	}
}
