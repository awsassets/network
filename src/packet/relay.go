package packet

import (
	"fmt"
	"net"

	"github.com/google/uuid"
)

func (c *PacketConstructor) MakeRelayDataPacket(data []byte, ip net.IP, destIP net.IP) RelayPacket {
	pkt := Packet(c.slice(RelayDataPacketHeaderLength + len(data)))

	pkt.SetType(PacketTypeRelay)

	r := RelayPacket(pkt)
	r.SetDestIP(destIP)
	r.SetType(PacketTypeData)

	datapkt := DataPacket(r.ToPacket())
	datapkt.SetIP(ip)
	datapkt.SetData(data)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad data packet creation"))
	}

	return r
}

func (c *PacketConstructor) MakeRelayDataPacketSize(size int, destIP net.IP) RelayPacket {
	pkt := Packet(c.slice(RelayDataPacketHeaderLength + size))

	pkt.SetType(PacketTypeRelay)

	r := RelayPacket(pkt)
	r.SetDestIP(destIP)
	r.SetType(PacketTypeData)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad data packet creation"))
	}

	return r
}

func (c *PacketConstructor) MakeRelayPingPacket(id uuid.UUID, ip net.IP, destIP net.IP) RelayPacket {
	pkt := Packet(c.slice(RelayPingPacketLength))

	pkt.SetType(PacketTypeRelay)

	r := RelayPacket(pkt)

	r.SetDestIP(destIP)
	r.SetType(PacketTypePing)

	ping := PingPacket(r.ToPacket())
	ping.SetID(id)
	ping.SetIP(ip)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad ping packet creation"))
	}

	return r
}

func (c *PacketConstructor) MakeRelayPongPacket(id uuid.UUID, destIP net.IP) RelayPacket {
	pkt := Packet(c.slice(RelayPongPacketLength))

	pkt.SetType(PacketTypeRelay)

	r := RelayPacket(pkt)

	r.SetDestIP(destIP)
	r.SetType(PacketTypePong)

	pong := PongPacket(r.ToPacket())

	pong.SetID(id)

	if !c.ToPacket().Valid() && pong.ID().String() == id.String() {
		panic(fmt.Errorf("bad pong packet creation"))
	}

	return r
}

func (c *PacketConstructor) MakeRelayPongAesPacket(id uuid.UUID, data []byte, hmac []byte, destIP net.IP) RelayPacket {
	pkt := Packet(c.slice(RelayPongAesPacketLength))

	pkt.SetType(PacketTypeRelay)

	r := RelayPacket(pkt)

	r.SetDestIP(destIP)
	r.SetType(PacketTypePongAes)

	pong := PongAesPacket(r.ToPacket())

	pong.SetID(id)
	pong.SetData(data)
	pong.SetHmac(hmac)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad pong aes packet creation"))
	}

	return r
}

func (c *PacketConstructor) MakeRelayExchangePacket(data []byte, ip net.IP, destIP net.IP) RelayPacket {
	pkt := Packet(c.slice(RelayExchangePacketHeaderLength + len(data)))

	pkt.SetType(PacketTypeRelay)

	r := RelayPacket(pkt)

	r.SetDestIP(destIP)
	r.SetType(PacketTypeExchange)

	exchange := ExchangePacket(r.ToPacket())
	exchange.SetIP(ip)
	exchange.SetData(data)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad exchange packet creation"))
	}

	return r
}

func (p RelayPacket) Valid() bool {
	if len(p) > RelayPacketHeaderLength {
		return p.ToPacket().Valid()
	}

	return false
}

func (p RelayPacket) SetType(t PacketType) {
	p[RelayPacketHeaderLength] = byte(t)
}

func (p RelayPacket) SetDestIP(ip net.IP) {
	copy(p[PacketTypeLength:PacketTypeLength+PacketIPv4Length], ip.To4())
}

func (p RelayPacket) Type() PacketType {
	if !p.Valid() {
		return 0
	}

	return PacketType(p[RelayPacketHeaderLength])
}

func (p RelayPacket) DestIP() net.IP {
	if !p.Valid() {
		return nil
	}

	return net.IPv4(p[PacketTypeLength], p[PacketTypeLength+1], p[PacketTypeLength+2], p[PacketTypeLength+3])
}

func (p RelayPacket) ToPacket() Packet {
	return Packet(p[RelayPacketHeaderLength:])
}
