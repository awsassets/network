package packet

import (
	"net"
)

func (c *PacketConstructor) MakeExchangePacket(data []byte, ip net.IP) ExchangePacket {
	pkt := Packet(c.slice(ExchangePacketHeaderLength + len(data)))

	pkt.SetType(PacketTypeExchange)

	exchange := ExchangePacket(pkt)
	exchange.SetIP(ip)
	exchange.SetData(data)

	if !c.ToPacket().Valid() {
		panic("bad exchange packet creation")
	}

	return exchange
}

func (p ExchangePacket) Valid() bool {
	return len(p) > ExchangePacketHeaderLength && Packet(p).Type() == PacketTypeExchange
}

func (p ExchangePacket) IP() net.IP {
	if !p.Valid() {
		return nil
	}

	return net.IPv4(p[1], p[2], p[3], p[4])
}

func (p ExchangePacket) Data() []byte {
	if !p.Valid() {
		return nil
	}

	return p[ExchangePacketHeaderLength:]
}

func (p ExchangePacket) SetIP(ip net.IP) {
	copy(p[1:5], ip.To4())
}

func (p ExchangePacket) SetData(data []byte) {
	copy(p[ExchangePacketHeaderLength:], data)
}
