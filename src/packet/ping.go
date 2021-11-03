package packet

import (
	"fmt"
	"net"

	"github.com/google/uuid"
)

func (c *PacketConstructor) MakePingPacket(id uuid.UUID, ip net.IP) PingPacket {
	pkt := Packet(c.slice(PingPacketLength))

	pkt.SetType(PacketTypePing)

	ping := PingPacket(pkt)
	ping.SetID(id)
	ping.SetIP(ip)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad ping packet creation"))
	}

	return ping
}

func (p PingPacket) Valid() bool {
	return len(p) == PingPacketLength && Packet(p).Type() == PacketTypePing
}

func (p PingPacket) IP() net.IP {
	if !p.Valid() {
		return nil
	}

	return net.IPv4(p[PacketTypeLength], p[PacketTypeLength+1], p[PacketTypeLength+2], p[PacketTypeLength+3])
}

func (p PingPacket) ID() uuid.UUID {
	if !p.Valid() {
		return uuid.UUID{}
	}

	id, _ := uuid.FromBytes(p[PacketTypeLength+PacketIPv4Length : PacketTypeLength+PacketIPv4Length+PacketIdLength])

	return id
}

func (p PingPacket) SetIP(ip net.IP) {
	copy(p[PacketTypeLength:PacketTypeLength+PacketIPv4Length], ip.To4())
}

func (p PingPacket) SetID(id uuid.UUID) {
	copy(p[PacketTypeLength+PacketIPv4Length:PacketTypeLength+PacketIPv4Length+PacketIdLength], id[:])
}
