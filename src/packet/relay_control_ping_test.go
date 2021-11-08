package packet

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_RelayControlPingPacket(t *testing.T) {
	pc := NewConstructor()

	tkn := make([]byte, PacketRelayControlPingTokenLength)

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	_, _ = rand.Read(tkn)

	id, _ := uuid.NewRandom()

	pc.MakeRelayControlPingPacket(id, tkn)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(RelayControlPingPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(RelayControlPingPacket(pc.ToPacket()).Token()), hash(tkn), "The token should be the same")
	assert.Equal(t, hash(RelayControlPingPacket(pc.ToTCP().ToPacket()).Token()), hash(tkn), "The token should be the same")
	assert.Equal(t, hash(RelayControlPingPacket(pc.ToUDP().ToPacket()).Token()), hash(tkn), "The token should be the same")

	assert.Equal(t, RelayControlPingPacket(pc.ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, RelayControlPingPacket(pc.ToTCP().ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, RelayControlPingPacket(pc.ToUDP().ToPacket()).ID(), id, "The id should be the same")
}

func Test_RelayControlPingPacketBad(t *testing.T) {
	assert.Equal(t, false, RelayControlPingPacket(nil).Valid(), "Invalid packets should not be valid")
	assert.Nil(t, RelayControlPingPacket(nil).Token(), "Invalid packets should have no token")
	assert.Equal(t, RelayControlPingPacket(nil).ID(), uuid.UUID{}, "Invalid packets should have no ID")
}
