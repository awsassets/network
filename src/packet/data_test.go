package packet

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_DataPacket(t *testing.T) {
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

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(MTU+DataPacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(DataPacket(pc.ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToTCP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToUDP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, DataPacket(pc.ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToTCP().ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToUDP().ToPacket()).IP(), ip, "The IP address should be the same")

	pc.MakeDataPacket(nil, ip)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(DataPacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(DataPacket(pc.ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToTCP().ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToUDP().ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")

	assert.Equal(t, DataPacket(pc.ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToTCP().ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToUDP().ToPacket()).IP(), ip, "The IP address should be the same")
}

func Test_DataPacketBad(t *testing.T) {
	assert.Equal(t, false, DataPacket(nil).Valid(), "Invalid packets should not be valid")
	assert.Nil(t, DataPacket(nil).IP(), "Invalid packets should have no IP")
	assert.Nil(t, DataPacket(nil).Data(), "Invalid packets should have no Data")
}

func Test_DataPacketSize(t *testing.T) {
	pc := NewConstructor()

	data := pc.Buffer()[DataPacketHeaderLength : DataPacketHeaderLength+MTU]

	_, _ = rand.Read(data)

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	ip := net.IPv4(1, 1, 1, 1)

	pc.MakeDataPacketSize(MTU).SetIP(ip)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(MTU+DataPacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(DataPacket(pc.ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToTCP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToUDP().ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, DataPacket(pc.ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToTCP().ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToUDP().ToPacket()).IP(), ip, "The IP address should be the same")

	pc.MakeDataPacketSize(0).SetIP(ip)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(DataPacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(DataPacket(pc.ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToTCP().ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(pc.ToUDP().ToPacket()).Data()), hash(nil), "The data should be the same as the packet content")

	assert.Equal(t, DataPacket(pc.ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToTCP().ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(pc.ToUDP().ToPacket()).IP(), ip, "The IP address should be the same")
}

func Test_RelayDataPacket(t *testing.T) {
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

	pc.MakeRelayDataPacket(data, ip, destIP)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(MTU+RelayDataPacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(DataPacket(RelayPacket(pc.ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(RelayPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket())).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, DataPacket(RelayPacket(pc.ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")

	assert.Equal(t, RelayPacket(pc.ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToTCP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToUDP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
}

func Test_RelayDataPacketSize(t *testing.T) {
	pc := NewConstructor()

	data := pc.Buffer()[RelayDataPacketHeaderLength : RelayDataPacketHeaderLength+MTU]

	_, _ = rand.Read(data)

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	ip := net.IPv4(1, 1, 1, 1)
	destIP := net.IPv4(2, 2, 2, 2)

	DataPacket(pc.MakeRelayDataPacketSize(MTU, destIP).ToPacket()).SetIP(ip)

	assert.Equal(t, pc.ToPacket().Valid(), true, "Packet should be valid")
	assert.Equal(t, pc.ToTCP().ToPacket().Valid(), true, "TCP packet should be valid")
	assert.Equal(t, pc.ToUDP().ToPacket().Valid(), true, "UDP packet should be valid")

	assert.Equal(t, pc.ToTCP().Size(), uint16(MTU+RelayDataPacketHeaderLength), "TCP size should be constant")
	assert.Equal(t, pc.Size(), pc.ToTCP().Size(), "Constructer size should be the same as the packet")

	assert.Equal(t, hash(DataPacket(RelayPacket(pc.ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(RelayPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket())).Data()), hash(data), "The data should be the same as the packet content")
	assert.Equal(t, hash(DataPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).Data()), hash(data), "The data should be the same as the packet content")

	assert.Equal(t, DataPacket(RelayPacket(pc.ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(RelayPacket(pc.ToTCP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")
	assert.Equal(t, DataPacket(RelayPacket(pc.ToUDP().ToPacket()).ToPacket()).IP(), ip, "The IP address should be the same")

	assert.Equal(t, RelayPacket(pc.ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToTCP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
	assert.Equal(t, RelayPacket(pc.ToUDP().ToPacket()).DestIP(), destIP, "The Dest IP address should be the same")
}
