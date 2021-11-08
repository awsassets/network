package packet

import (
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_PongPacket(t *testing.T) {
	pc := NewConstructor()

	id, _ := uuid.NewRandom()

	pc.MakePongPacket(id)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(PongPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, PongPacket(pc.ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PongPacket(pc.ToTCP().ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PongPacket(pc.ToUDP().ToPacket()).ID(), id, "The id should be the same")
}

func Test_PongPacketBad(t *testing.T) {
	assert.Equal(t, false, PongPacket(nil).Valid(), "Invalid packets should not be valid")
	assert.Equal(t, PongPacket(nil).ID(), uuid.UUID{}, "Invalid packets should have no ID")
}

func Test_RelayPongPacket(t *testing.T) {
	pc := NewConstructor()

	id, _ := uuid.NewRandom()

	destIP := net.IPv4(2, 2, 2, 2)

	pc.MakeRelayPongPacket(id, destIP)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(RelayPongPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, PongPacket(RelayPacket(pc.ToPacket()).ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PongPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PongPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).ID(), id, "The id should be the same")

	assert.Equal(t, RelayPacket(pc.ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToTCP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToUDP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
}
