package netutil

import (
	"net"
	"runtime"

	"github.com/libp2p/go-reuseport"
)

func ResolveAddr(network, address string) (net.Addr, error) {
	switch network {
	default:
		return nil, net.UnknownNetworkError(network)
	case "ip", "ip4", "ip6":
		return net.ResolveIPAddr(network, address)
	case "tcp", "tcp4", "tcp6":
		return net.ResolveTCPAddr(network, address)
	case "udp", "udp4", "udp6":
		return net.ResolveUDPAddr(network, address)
	case "unix", "unixgram", "unixpacket":
		return net.ResolveUnixAddr(network, address)
	}
}

func DialUDP(laddr, raddr string) ([]*net.UDPConn, error) {
	conns := make([]*net.UDPConn, runtime.GOMAXPROCS(0))

	l, err := ResolveAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	r, err := ResolveAddr("udp", raddr)
	if err != nil {
		return nil, err
	}

	for i := range conns {
		conn, err := reuseport.Dial("udp", l.String(), r.String())
		if err != nil {
			return nil, err
		}

		conns[i] = conn.(*net.UDPConn)
	}
	return conns, nil
}

func ListenUDP(laddr string) ([]*net.UDPConn, error) {
	conns := make([]*net.UDPConn, runtime.GOMAXPROCS(0))

	l, err := ResolveAddr("udp", laddr)
	if err != nil {
		return nil, err
	}

	for i := range conns {
		conn, err := reuseport.ListenPacket("udp", l.String())
		if err != nil {
			return nil, err
		}

		conns[i] = conn.(*net.UDPConn)
	}
	return conns, nil
}

func ListenTCP(laddr string) ([]*net.TCPListener, error) {
	conns := make([]*net.TCPListener, runtime.GOMAXPROCS(0))

	l, err := ResolveAddr("udp", laddr)
	if err != nil {
		return nil, err
	}

	for i := range conns {
		conn, err := reuseport.Listen("tcp", l.String())
		if err != nil {
			return nil, err
		}

		conns[i] = conn.(*net.TCPListener)
	}
	return conns, nil
}

func DialTCP(laddr, raddr string) ([]*net.TCPConn, error) {
	conns := make([]*net.TCPConn, runtime.GOMAXPROCS(0))

	l, err := ResolveAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	r, err := ResolveAddr("udp", raddr)
	if err != nil {
		return nil, err
	}

	for i := range conns {
		conn, err := reuseport.Dial("tcp", l.String(), r.String())
		if err != nil {
			return nil, err
		}

		conns[i] = conn.(*net.TCPConn)
	}
	return conns, nil
}
