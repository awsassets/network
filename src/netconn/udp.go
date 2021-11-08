package netconn

import (
	"net"
)

type UDPConn interface {
	net.Conn
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
}

type MockUDPConn struct {
	MockConn
	WriteToUDPFunc  func([]byte, *net.UDPAddr) (int, error)
	ReadFromUDPFunc func([]byte) (int, *net.UDPAddr, error)
}

func (m MockUDPConn) WriteToUDP(data []byte, addr *net.UDPAddr) (int, error) {
	return m.WriteToUDPFunc(data, addr)
}

func (m MockUDPConn) ReadFromUDP(data []byte) (int, *net.UDPAddr, error) {
	return m.ReadFromUDPFunc(data)
}
