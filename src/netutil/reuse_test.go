package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ResolveAddr(t *testing.T) {
	_, err := ResolveAddr("tcp", "127.0.0.1:0")
	assert.ErrorIs(t, err, nil, "address parses correctly")

	_, err = ResolveAddr("udp", "127.0.0.1:0")
	assert.ErrorIs(t, err, nil, "address parses correctly")
}

func Test_UDP(t *testing.T) {
	listenConns, err := ListenUDP("")
	assert.ErrorIs(t, err, nil, "conns created correctly")
	defer func() {
		for _, v := range listenConns {
			v.Close()
		}
	}()

	addr := listenConns[0].LocalAddr().String()

	udpConns, err := DialUDP("", addr)
	assert.ErrorIs(t, err, nil, "conns created correctly")
	defer func() {
		for _, v := range udpConns {
			v.Close()
		}
	}()
}

func Test_TCP(t *testing.T) {
	listenConns, err := ListenTCP("")
	assert.ErrorIs(t, err, nil, "conns created correctly")
	defer func() {
		for _, v := range listenConns {
			v.Close()
		}
	}()

	addr := listenConns[0].Addr().String()

	udpConns, err := DialTCP("", addr)
	assert.ErrorIs(t, err, nil, "conns created correctly")
	defer func() {
		for _, v := range udpConns {
			v.Close()
		}
	}()
}
