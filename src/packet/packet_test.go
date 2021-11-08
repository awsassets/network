package packet

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_Packet(t *testing.T) {
	pkt := Packet(nil)

	assert.Equal(t, PacketTypeInvalid, pkt.Type(), "Invalid packets should have 0 type")

	pc := NewConstructor()

	data := make([]byte, MTU)

	_, _ = rand.Read(data)

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	ip := net.IPv4(1, 1, 1, 1)

	pc.MakeDataPacket(data, ip)

	pkt = pc.ToPacket()

	copy := pkt.Copy()

	assert.Equal(t, hash(pkt), hash(copy), "The copy should have the same hash")

	_, _ = rand.Read(data)

	pc.MakeDataPacket(data, ip)

	assert.NotEqual(t, hash(pkt), hash(copy), "The copy should have a different the same hash")

	copy = make([]byte, len(pkt))

	pkt.CopyTo(copy)

	assert.Equal(t, hash(pkt), hash(copy), "The copy should have the same hash")

	_, _ = rand.Read(data)

	pc.MakeDataPacket(data, ip)

	assert.NotEqual(t, hash(pkt), hash(copy), "The copy should have a different the same hash")

	Packet(nil).SetType(0)

	assert.Equal(t, false, Packet(nil).Valid(), "Bad packet is invalid")
}
