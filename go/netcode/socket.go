package netcode

import (
	"net"
)

const (
	SOCKET_ERROR_NONE = iota
	SOCKET_ERROR_CREATE_FAILED
	SOCKET_ERROR_SET_NON_BLOCKING_FAILED
	SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED
	SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED
	SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED
	SOCKET_ERROR_BIND_IPV4_FAILED
	SOCKET_ERROR_BIND_IPV6_FAILED
	SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED
	SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED
)

type Socket struct {
	Address *net.UDPAddr
	Conn *net.UDPConn
}

func NewSocket() *Socket {
	s := &Socket{}
	return s
}

func (s *Socket) Create(address *net.UDPAddr, sendsize, recvsize int) error {
	conn, err := net.ListenUDP(address.Network(), address)
	if err != nil {
		return err
	}

	if err := conn.SetReadBuffer(recvsize); err != nil {
		return err
	}

	if err := conn.SetWriteBuffer(sendsize); err != nil {
		return err
	}

	s.Conn = conn
	return nil
}

func (s *Socket) Send(destination *net.UDPAddr, data []byte) error {
	if s.Conn == nil {
		return nil
	}

	length, err := s.Conn.WriteTo(data, destination)
	if err != nil {
		return err
	}

	if length != len(data) {
		// error writing all data
		return nil
	}
	return nil
}

func (s *Socket) Recv(source *net.Addr, data []byte, maxsize uint) error {
	return nil
}


func (s *Socket) Destroy() {
	s.Conn.Close()
}

