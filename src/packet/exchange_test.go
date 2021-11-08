package packet

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_ExchangePacket(t *testing.T) {
	pc := NewConstructor()

	data := make([]byte, MTU)

	_, _ = rand.Read(data)

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	ip := net.IPv4(1, 1, 1, 1)

	pc.MakeExchangePacket(data, ip)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(MTU+ExchangePacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(ExchangePacket(pc.ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(ExchangePacket(pc.ToTCP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(ExchangePacket(pc.ToUDP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, ExchangePacket(pc.ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, ExchangePacket(pc.ToTCP().ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, ExchangePacket(pc.ToUDP().ToPacket()).IP(), ip, "The IP address should be the same")

	pc.MakeExchangePacket(nil, ip)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(ExchangePacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(ExchangePacket(pc.ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")
	assert.Equal(t, hash(ExchangePacket(pc.ToTCP().ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")
	assert.Equal(t, hash(ExchangePacket(pc.ToUDP().ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")

	assert.Equal(t, ExchangePacket(pc.ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, ExchangePacket(pc.ToTCP().ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, ExchangePacket(pc.ToUDP().ToPacket()).IP(), ip, "The IP address should be the same")
}

func Test_ExchangePacketBad(t *testing.T) {
	assert.Equal(t, false, ExchangePacket(nil).Valid(), "Invalid packets should not be valid")
	assert.Nil(t, ExchangePacket(nil).IP(), "Invalid packets should have no IP")
	assert.Nil(t, ExchangePacket(nil).Data(), "Invalid packets should have no Data")
}

func Test_RelayExchangePacket(t *testing.T) {
	pc := NewConstructor()

	data := make([]byte, MTU)

	_, _ = rand.Read(data)

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	ip := net.IPv4(1, 1, 1, 1)
	destIP := net.IPv4(2, 2, 2, 2)

	pc.MakeRelayExchangePacket(data, ip, destIP)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(MTU+RelayExchangePacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(ExchangePacket(RelayPacket(pc.ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(ExchangePacket(RelayPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket())).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(ExchangePacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, ExchangePacket(RelayPacket(pc.ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, ExchangePacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, ExchangePacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")

	assert.Equal(t, RelayPacket(pc.ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToTCP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToUDP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
}
