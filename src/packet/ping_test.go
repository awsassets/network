package packet

import (
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_PingPacket(t *testing.T) {
	pc := NewConstructor()

	ip := net.IPv4(1, 1, 1, 1)

	id, _ := uuid.NewRandom()

	pc.MakePingPacket(id, ip)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(PingPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, PingPacket(pc.ToPacket()).ID(), id, "The data should be the same as the packet content")
	assert.Equal(t, PingPacket(pc.ToTCP().ToPacket()).ID(), id, "The data should be the same as the packet content")
	assert.Equal(t, PingPacket(pc.ToUDP().ToPacket()).ID(), id, "The data should be the same as the packet content")

	assert.Equal(t, PingPacket(pc.ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, PingPacket(pc.ToTCP().ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, PingPacket(pc.ToUDP().ToPacket()).IP(), ip, "The IP address should be the same")
}

func Test_PingPacketBad(t *testing.T) {
	assert.Equal(t, false, PingPacket(nil).Valid(), "Invalid packets should not be valid")
	assert.Nil(t, PingPacket(nil).IP(), "Invalid packets should have no IP")
	assert.Equal(t, PingPacket(nil).ID(), uuid.UUID{}, "Invalid packets should have no ID")
}

func Test_RelayPingPacket(t *testing.T) {
	pc := NewConstructor()

	ip := net.IPv4(1, 1, 1, 1)

	destIP := net.IPv4(2, 2, 2, 2)

	id, _ := uuid.NewRandom()

	pc.MakeRelayPingPacket(id, ip, destIP)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(RelayPingPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, PingPacket(RelayPacket(pc.ToPacket()).ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PingPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PingPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).ID(), id, "The id should be the same")

	assert.Equal(t, PingPacket(RelayPacket(pc.ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, PingPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, PingPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")

	assert.Equal(t, RelayPacket(pc.ToPacket()).DestIP(), destIP, "The destIP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToTCP().ToPacket()).DestIP(), destIP, "The destIP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToUDP().ToPacket()).DestIP(), destIP, "The destIP address should be the same")
}
