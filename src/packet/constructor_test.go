package packet

import (
	"encoding/hex"
	"math/rand"
	"net"
	"testing"

	"github.com/disembark/network/src/netconn"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_ConstructorTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.ErrorIs(t, err, nil, "The listener is made")

	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		assert.ErrorIs(t, err, nil, "Connection is made")
		connCh <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	assert.ErrorIs(t, err, nil, "Connection is made")
	defer client.Close()
	server := <-connCh
	close(connCh)
	defer server.Close()

	pcClient := NewConstructor()
	pcServer := NewConstructor()

	data := make([]byte, MTU)
	_, _ = rand.Read(data)

	ip := net.IPv4(1, 1, 1, 1)

	cPkt := Packet(pcClient.MakeDataPacket(data, ip)).Copy()

	_, err = client.Write(pcClient.ToTCP())
	assert.ErrorIs(t, err, nil, "We can write a packet")

	err = pcServer.ReadTCP(server)
	assert.ErrorIs(t, err, nil, "We read a packet")

	sPkt := pcServer.ToPacket()

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	assert.Equal(t, hash(cPkt), hash(sPkt), "We read the packet correctly")
}

func Test_ConstructorUDP(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.ErrorIs(t, err, nil, "The listener is made")
	defer ln.Close()

	client, err := net.Dial("udp", ln.LocalAddr().String())
	assert.ErrorIs(t, err, nil, "Connection is made")
	defer client.Close()

	pcClient := NewConstructor()
	pcServer := NewConstructor()

	data := make([]byte, MTU)
	_, _ = rand.Read(data)

	ip := net.IPv4(1, 1, 1, 1)

	cPkt := Packet(pcClient.MakeDataPacket(data, ip)).Copy()

	_, err = client.Write(pcClient.ToUDP())
	assert.ErrorIs(t, err, nil, "We can write a packet")

	_, err = pcServer.ReadUDP(ln.(netconn.UDPConn))
	assert.ErrorIs(t, err, nil, "We read a packet")

	sPkt := pcServer.ToPacket()

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	assert.Equal(t, hash(cPkt), hash(sPkt), "We read the packet correctly")
}
