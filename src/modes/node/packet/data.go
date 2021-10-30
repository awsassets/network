package packet

import (
	"net"
)

func (c *PacketConstructor) MakeDataPacket(data []byte, ip net.IP) DataPacket {
	pkt := Packet(c.slice(DataPacketHeaderLength + len(data)))

	pkt.SetType(PacketTypeData)

	datapkt := DataPacket(pkt)
	datapkt.SetIP(ip)
	datapkt.SetData(data)

	if !c.ToPacket().Valid() {
		panic("bad data packet creation")
	}

	return datapkt
}

func (p DataPacket) Valid() bool {
	return len(p) > DataPacketHeaderLength && Packet(p).Type() == PacketTypeData
}

func (p DataPacket) IP() net.IP {
	if !p.Valid() {
		return nil
	}

	return net.IPv4(p[1], p[2], p[3], p[4])
}

func (p DataPacket) Data() []byte {
	if !p.Valid() {
		return nil
	}

	return p[ExchangePacketHeaderLength:]
}

func (p DataPacket) SetIP(ip net.IP) {
	copy(p[1:5], ip.To4())
}

func (p DataPacket) SetData(data []byte) {
	copy(p[ExchangePacketHeaderLength:], data)
}
