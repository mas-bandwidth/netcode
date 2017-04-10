package netcode

import (
	//"errors"
	"log"
	"net"
	"time"
)

const (
	SOCKET_RCVBUF_SIZE = 1024 * 1024
	SOCKET_SNDBUF_SIZE = 1024 * 1024
)

type NetcodeConn struct {
	address  *net.UDPAddr
	conn     *net.UDPConn
	closeCh  chan struct{}
	isClosed bool
	xmit     *Queue
	recv     *Queue
}

func NewNetcodeConn(address *net.UDPAddr) *NetcodeConn {
	c := &NetcodeConn{}
	c.address = address
	c.closeCh = make(chan struct{})
	c.xmit = NewQueue()
	c.recv = NewQueue()
	return c
}

func (c *NetcodeConn) Read(b []byte) (int, error) {
	buf := c.Recv()
	copy(b, buf)
	return len(buf), nil
}

func (c *NetcodeConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *NetcodeConn) Close() error {
	c.xmit = nil
	c.recv = nil
	if !c.isClosed {
		close(c.closeCh)
	}
	c.isClosed = true
	return c.conn.Close()
}

func (c *NetcodeConn) SetReadBuffer(bytes int) error {
	return c.conn.SetReadBuffer(bytes)
}

func (c *NetcodeConn) SetWriteBuffer(bytes int) error {
	return c.conn.SetWriteBuffer(bytes)
}

func (c *NetcodeConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *NetcodeConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *NetcodeConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// LocalAddr returns the local network address.
func (c *NetcodeConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *NetcodeConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *NetcodeConn) Dial() error {
	var err error
	c.conn, err = net.DialUDP(c.address.Network(), nil, c.address)
	if err != nil {
		return err
	}
	return c.create()
}

func (c *NetcodeConn) create() error {
	c.conn.SetReadBuffer(SOCKET_RCVBUF_SIZE)
	c.conn.SetWriteBuffer(SOCKET_SNDBUF_SIZE)
	go c.readLoop()
	return nil
}

func (c *NetcodeConn) Listen() error {
	var err error
	log.Printf("%s\n", c.address.Network())
	c.conn, err = net.ListenUDP(c.address.Network(), c.address)
	if err != nil {
		return err
	}
	c.create()
	return err
}

func (c *NetcodeConn) receiver(ch chan []byte) {
	for {
		data := make([]byte, MAX_PACKET_BYTES)
		if n, from, err := c.conn.ReadFromUDP(data); err == nil {
			if !from.IP.Equal(c.address.IP) {
				log.Printf("unknown server address sent us data expected: " + c.address.String() + " but came from: " + from.String())
			}
			select {
			case ch <- data[:n]:
			case <-c.closeCh:
				return
			}
		} else {
			log.Printf("error reading packet data: %s\n", err)
			return
		}
	}
}

func (c *NetcodeConn) readLoop() {
	dataCh := make(chan []byte, MAX_PACKET_BYTES)
	go c.receiver(dataCh)
	for {
		select {
		case data := <-dataCh:
			c.recv.Push(data)
		case <-c.closeCh:
			return
		}
	}
}

func (c *NetcodeConn) Recv() []byte {
	return c.recv.Pop()
}
