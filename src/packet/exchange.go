package packet

import (
	"fmt"
	"net"
)

/*
The exchange packet is used to exchange an AES key used to encrypt data packets.

The structure looks like this.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       5       |                   IPv4 Address                :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :               |                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                  N bytes of packet payload                    :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


If the packet is a TCP packet then there are 2 extra bytes in front
of this which deonte the total data left in the packet.
Like this.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   BE uint16 remaining length  |       5       |     IPv4      :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                   Address                     |               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                  N bytes of packet payload                    :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	:                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

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
	return len(p) >= ExchangePacketHeaderLength && Packet(p).Type() == PacketTypeExchange
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
