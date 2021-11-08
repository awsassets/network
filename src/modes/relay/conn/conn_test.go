package conn_store

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"

	"github.com/disembark/network/src/loadbalancer"
	"github.com/disembark/network/src/netconn"
	"github.com/disembark/network/src/packet"
	node_store "github.com/disembark/network/src/store/node"
	"github.com/disembark/network/src/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_Store(t *testing.T) {
	nodes := node_store.New()
	lb := loadbalancer.New()
	store := New(nodes, lb).(*StoreInstance)

	nodes.SetNode("test", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			IP:    "10.10.0.1",
			Name:  "test",
			Relay: true,
		},
	})

	conn := store.New("10.10.0.1")
	assert.NotNil(t, conn, "the connection is not nil")
	conn = store.Get("10.10.0.1")
	assert.NotNil(t, conn, "the connection is not nil")

	store.cleanup()
	store.Stop("10.10.0.1")
	conn = store.Get("10.10.0.1")
	assert.Nil(t, conn, "the connection is nil")
}

func Test_Conn(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	nodes := node_store.New()
	lb := loadbalancer.New()
	store := New(nodes, lb).(*StoreInstance)

	nodes.SetNode("test", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			IP:    "10.10.0.1",
			Name:  "test",
			Relay: true,
		},
	})

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	conn := store.New("10.10.0.1").(*ConnInstance)

	pc := packet.NewConstructor()
	pktTcpCh := make(chan []byte, 100)
	pktUdpCh := make(chan []byte, 100)
	defer close(pktTcpCh)
	defer close(pktUdpCh)

	mockUDPConn := netconn.MockUDPConn{
		ReadFromUDPFunc: func(b []byte) (int, *net.UDPAddr, error) {
			pkt, ok := <-pktUdpCh
			if !ok {
				return 0, nil, io.EOF
			}
			return copy(b, pkt), nil, nil
		},
		WriteToUDPFunc: func(b []byte, addr *net.UDPAddr) (int, error) {
			pktUdpCh <- b
			return len(b), nil
		},
		MockConn: netconn.MockConn{
			WriteFunc: func(b []byte) (n int, err error) {
				pktUdpCh <- b
				return len(b), nil
			},
			ReadFunc: func(b []byte) (n int, err error) {
				pkt, ok := <-pktUdpCh
				if !ok {
					return 0, io.EOF
				}
				return copy(b, pkt), nil
			},
			CloseFunc: func() error {
				return nil
			},
		},
	}

	lb.AddItem(mockUDPConn)

	mockTCPConn := netconn.MockConn{
		WriteFunc: func(b []byte) (n int, err error) {
			pktTcpCh <- b
			return len(b), nil
		},
		ReadFunc: func(b []byte) (n int, err error) {
			pkt := <-pktTcpCh
			return copy(b, pkt), nil
		},
		CloseFunc: func() error {
			return nil
		},
	}

	mockTCPConnReader := bufio.NewReader(mockTCPConn)

	conn.RegisterPing(mockTCPConn)
	conn.RegisterPingUDP(&net.UDPAddr{})

	{
		conn.forceTCP = true
		conn.forceUDP = false

		data := make([]byte, packet.MTU)
		_, _ = rand.Read(data)

		pc.MakeDataPacket(data, net.ParseIP("10.10.0.2"))
		err := conn.WriteTCP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "no error when writing tcp packets")

		err = pc.ReadTCP(mockTCPConnReader)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet read is valid")
		assert.Equal(t, packet.PacketTypeData, pc.ToPacket().Type(), "the packet read is data")
		assert.Equal(t, hash(packet.DataPacket(pc.ToPacket()).Data()), hash(data), "the content is intact")
	}

	{
		conn.forceTCP = false
		conn.forceUDP = true

		data := make([]byte, packet.MTU)
		_, _ = rand.Read(data)

		pc.MakeDataPacket(data, net.ParseIP("10.10.0.2"))
		err := conn.WriteUDP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "no error when writing tcp packets")

		_, err = pc.ReadUDP(mockUDPConn)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet read is valid")
		assert.Equal(t, packet.PacketTypeData, pc.ToPacket().Type(), "the packet read is data")
		assert.Equal(t, hash(packet.DataPacket(pc.ToPacket()).Data()), hash(data), "the content is intact")
	}

	{
		conn.forceTCP = false
		conn.forceUDP = true

		data := make([]byte, packet.MTU)
		_, _ = rand.Read(data)

		pc.MakeDataPacket(data, net.ParseIP("10.10.0.2"))
		err := conn.WriteTCP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "no error when writing tcp packets")

		_, err = pc.ReadUDP(mockUDPConn)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet read is valid")
		assert.Equal(t, packet.PacketTypeData, pc.ToPacket().Type(), "the packet read is data")
		assert.Equal(t, hash(packet.DataPacket(pc.ToPacket()).Data()), hash(data), "the content is intact")
	}

	{
		conn.forceTCP = true
		conn.forceUDP = false

		data := make([]byte, packet.MTU)
		_, _ = rand.Read(data)

		pc.MakeDataPacket(data, net.ParseIP("10.10.0.2"))
		err := conn.WriteUDP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "no error when writing tcp packets")

		err = pc.ReadTCP(mockTCPConnReader)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet read is valid")
		assert.Equal(t, packet.PacketTypeData, pc.ToPacket().Type(), "the packet read is data")
		assert.Equal(t, hash(packet.DataPacket(pc.ToPacket()).Data()), hash(data), "the content is intact")
	}

	{
		conn.forceTCP = true
		conn.forceUDP = true

		data := make([]byte, packet.MTU)
		_, _ = rand.Read(data)

		pc.MakeDataPacket(data, net.ParseIP("10.10.0.2"))
		err := conn.WriteTCP(pc.ToTCP())
		assert.ErrorIs(t, err, ErrNoRoute, "error when writing tcp packets")
	}

	{
		conn.forceTCP = true
		conn.forceUDP = true

		data := make([]byte, packet.MTU)
		_, _ = rand.Read(data)

		pc.MakeDataPacket(data, net.ParseIP("10.10.0.2"))
		err := conn.WriteUDP(pc.ToTCP())
		assert.ErrorIs(t, err, ErrNoRoute, "error when writing tcp packets")
	}
}
