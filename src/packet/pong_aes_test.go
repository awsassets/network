package packet

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_PongAesPacket(t *testing.T) {
	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	pc := NewConstructor()

	id, _ := uuid.NewRandom()

	data := make([]byte, PacketPongAesDataLength)

	_, _ = rand.Read(data)

	hmac := make([]byte, PacketPongAesHmacLength)

	_, _ = rand.Read(hmac)

	pc.MakePongAesPacket(id, data, hmac)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(PongAesPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(PongAesPacket(pc.ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(PongAesPacket(pc.ToTCP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(PongAesPacket(pc.ToUDP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, PongAesPacket(pc.ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PongAesPacket(pc.ToTCP().ToPacket()).ID(), id, "The id should be the same")
	assert.Equal(t, PongAesPacket(pc.ToUDP().ToPacket()).ID(), id, "The id should be the same")

	assert.Equal(t, hash(PongAesPacket(pc.ToPacket()).Hmac()), hash(hmac), "The IP address should be the same")
	assert.Equal(t, hash(PongAesPacket(pc.ToTCP().ToPacket()).Hmac()), hash(hmac), "The IP address should be the same")
	assert.Equal(t, hash(PongAesPacket(pc.ToUDP().ToPacket()).Hmac()), hash(hmac), "The IP address should be the same")
}

func Test_PongAesPacketBad(t *testing.T) {
	assert.Equal(t, false, PongAesPacket(nil).Valid(), "Invalid packets should not be valid")
	assert.Nil(t, PongAesPacket(nil).Hmac(), "Invalid packets should have no IP")
	assert.Nil(t, PongAesPacket(nil).Data(), "Invalid packets should have no Data")
	assert.Equal(t, PongAesPacket(nil).ID(), uuid.UUID{}, "Invalid packets should have no ID")
}

func Test_RelayPongAesPacket(t *testing.T) {
	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	pc := NewConstructor()

	id, _ := uuid.NewRandom()

	data := make([]byte, PacketPongAesDataLength)

	_, _ = rand.Read(data)

	hmac := make([]byte, PacketPongAesHmacLength)

	_, _ = rand.Read(hmac)

	destIP := net.IPv4(1, 1, 1, 1)

	pc.MakeRelayPongAesPacket(id, data, hmac, destIP)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(RelayPongAesPacketLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(PongAesPacket(RelayPacket(pc.ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(PongAesPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(PongAesPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, hash(PongAesPacket(RelayPacket(pc.ToPacket()).ToPacket()).Hmac()), hash(hmac), "The IP address should be the same")
	assert.Equal(t, hash(PongAesPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).Hmac()), hash(hmac), "The IP address should be the same")
	assert.Equal(t, hash(PongAesPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).Hmac()), hash(hmac), "The IP address should be the same")

	assert.Equal(t, RelayPacket(pc.ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToTCP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToUDP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
}
