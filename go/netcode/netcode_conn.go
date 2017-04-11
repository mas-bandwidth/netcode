package netcode

import (
	"errors"
	"log"
	"net"
)

type netcodeData struct {
	data []byte
	from *net.UDPAddr
}

const (
	SOCKET_RCVBUF_SIZE = 1024 * 1024
	SOCKET_SNDBUF_SIZE = 1024 * 1024
)

type NetcodeRecvHandler func(data []byte, addr *net.UDPAddr)

type NetcodeConn struct {
	conn     *net.UDPConn
	closeCh  chan struct{}
	isClosed bool

	recvSize int
	sendSize int
	maxBytes int

	recvHandlerFn NetcodeRecvHandler
}

func NewNetcodeConn() *NetcodeConn {
	c := &NetcodeConn{}

	c.isClosed = true
	c.maxBytes = MAX_PACKET_BYTES
	c.recvSize = SOCKET_RCVBUF_SIZE
	c.sendSize = SOCKET_SNDBUF_SIZE
	return c
}

func (c *NetcodeConn) SetRecvHandler(recvHandlerFn NetcodeRecvHandler) {
	c.recvHandlerFn = recvHandlerFn
}

func (c *NetcodeConn) Write(b []byte) (int, error) {
	if c.isClosed {
		return -1, errors.New("unable to write, socket has been closed")
	}
	return c.conn.Write(b)
}

func (c *NetcodeConn) WriteTo(b []byte, to *net.UDPAddr) (int, error) {
	if c.isClosed {
		return -1, errors.New("unable to write, socket has been closed")
	}
	return c.conn.WriteTo(b, to)
}

func (c *NetcodeConn) Close() error {
	if !c.isClosed {
		close(c.closeCh)
	}
	c.isClosed = true
	return c.conn.Close()
}

func (c *NetcodeConn) SetReadBuffer(bytes int) {
	c.recvSize = bytes
}

func (c *NetcodeConn) SetWriteBuffer(bytes int) {
	c.sendSize = bytes
}

// LocalAddr returns the local network address.
func (c *NetcodeConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *NetcodeConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *NetcodeConn) Dial(address *net.UDPAddr) error {
	var err error

	if c.recvHandlerFn == nil {
		return errors.New("packet handler must be set before calling listen")
	}

	c.closeCh = make(chan struct{})
	c.conn, err = net.DialUDP(address.Network(), nil, address)
	if err != nil {
		return err
	}
	return c.create()
}

func (c *NetcodeConn) Listen(address *net.UDPAddr) error {
	var err error

	if c.recvHandlerFn == nil {
		return errors.New("packet handler must be set before calling listen")
	}

	c.conn, err = net.ListenUDP(address.Network(), address)
	if err != nil {
		return err
	}

	c.create()
	return err
}

func (c *NetcodeConn) create() error {
	c.isClosed = false
	c.conn.SetReadBuffer(c.recvSize)
	c.conn.SetWriteBuffer(c.sendSize)
	go c.readLoop()
	return nil
}

func (c *NetcodeConn) receiver(ch chan *netcodeData) {
	for {

		if netData, err := c.read(); err == nil {
			select {
			case ch <- netData:
			case <-c.closeCh:
				return
			}
		} else {
			log.Printf("error reading data from socket: %s\n", err)
		}

	}
}

func (c *NetcodeConn) read() (*netcodeData, error) {
	var n int
	var from *net.UDPAddr
	var err error

	netData := &netcodeData{}
	netData.data = make([]byte, c.maxBytes)

	n, from, err = c.conn.ReadFromUDP(netData.data)
	if err != nil {
		return nil, err
	}

	netData.from = from
	netData.data = netData.data[:n]
	return netData, nil
}

func (c *NetcodeConn) readLoop() {
	dataCh := make(chan *netcodeData)
	go c.receiver(dataCh)
	for {
		select {
		case data := <-dataCh:
			c.recvHandlerFn(data.data, data.from)
		case <-c.closeCh:
			return
		}
	}
}
