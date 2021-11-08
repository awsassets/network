package netconn

import (
	"net"
	"time"
)

type Conn interface {
	net.Conn
}

type MockConn struct {
	ReadFunc             func(b []byte) (n int, err error)
	WriteFunc            func(b []byte) (n int, err error)
	CloseFunc            func() error
	LocalAddrFunc        func() net.Addr
	RemoteAddrFunc       func() net.Addr
	SetDeadlineFunc      func(t time.Time) error
	SetReadDeadlineFunc  func(t time.Time) error
	SetWriteDeadlineFunc func(t time.Time) error
}

func (m MockConn) Read(b []byte) (n int, err error) {
	return m.ReadFunc(b)
}

func (m MockConn) Write(b []byte) (n int, err error) {
	return m.WriteFunc(b)
}

func (m MockConn) Close() error {
	return m.CloseFunc()
}

func (m MockConn) LocalAddr() net.Addr {
	return m.LocalAddrFunc()
}

func (m MockConn) RemoteAddr() net.Addr {
	return m.RemoteAddrFunc()
}

func (m MockConn) SetDeadline(t time.Time) error {
	return m.SetDeadlineFunc(t)
}

func (m MockConn) SetReadDeadline(t time.Time) error {
	return m.SetReadDeadlineFunc(t)
}

func (m MockConn) SetWriteDeadline(t time.Time) error {
	return m.SetWriteDeadlineFunc(t)
}
