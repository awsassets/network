package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RelayPacket(t *testing.T) {
	pkt := RelayPacket(nil)

	assert.Nil(t, pkt.ToPacket(), "The packet should be nil")
	assert.Equal(t, pkt.Type(), PacketTypeInvalid, "The packet type is invalid")
	assert.Equal(t, pkt.Valid(), false, "The packet is invalid")
}
