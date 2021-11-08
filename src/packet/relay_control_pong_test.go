package packet

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_RelayControlPongPacket(t *testing.T) {
	pc := NewConstructor()

	id, _ := uuid.NewRandom()

	pc.MakeRelayControlPongPacket(id)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(RelayControlPongPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, RelayControlPongPacket(pc.ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, RelayControlPongPacket(pc.ToTCP().ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, RelayControlPongPacket(pc.ToUDP().ToPacket()).ID(), id, "The id should be the same")
}

func Test_RelayControlPongPacketBad(t *testing.T) {
	assert.Equal(t, false, RelayControlPongPacket(nil).Valid(), "Invalid packets should not be valid")
	assert.Equal(t, RelayControlPongPacket(nil).ID(), uuid.UUID{}, "Invalid packets should have no ID")
}
