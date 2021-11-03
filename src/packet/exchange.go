package packet

import (
	"fmt"
	"net"
)

func (c *PacketConstructor) MakeExchangePacket(data []byte, ip net.IP) ExchangePacket {
	pkt := Packet(c.slice(ExchangePacketHeaderLength + len(data)))

	pkt.SetType(PacketTypeExchange)

	exchange := ExchangePacket(pkt)
	exchange.SetIP(ip)
	exchange.SetData(data)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad exchange packet creation"))
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

	return net.IPv4(p[PacketTypeLength], p[PacketTypeLength+1], p[PacketTypeLength+2], p[PacketTypeLength+3])
}

func (p ExchangePacket) Data() []byte {
	if !p.Valid() {
		return nil
	}

	return p[ExchangePacketHeaderLength:]
}

func (p ExchangePacket) SetIP(ip net.IP) {
	copy(p[PacketTypeLength:PacketTypeLength+PacketIPv4Length], ip.To4())
}

func (p ExchangePacket) SetData(data []byte) {
	copy(p[ExchangePacketHeaderLength:], data)
}
