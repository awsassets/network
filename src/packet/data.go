package packet

import (
	"fmt"
	"net"
)

/*
The data packet is used to transfer packets such as UDP or TCP packets.
The entire packet is stored within the data portion of the data packet.

The structure looks like this.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      1        |                   IPv4 Address                :
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
    |   BE uint16 remaining length  |       1       |      IPv4     :
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

func (c *PacketConstructor) MakeDataPacket(data []byte, ip net.IP) DataPacket {
	pkt := Packet(c.slice(DataPacketHeaderLength + len(data)))

	pkt.SetType(PacketTypeData)

	datapkt := DataPacket(pkt)
	datapkt.SetIP(ip)
	datapkt.SetData(data)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad data packet creation"))
	}

	return datapkt
}

func (c *PacketConstructor) MakeDataPacketSize(size int) DataPacket {
	pkt := Packet(c.slice(DataPacketHeaderLength + size))

	pkt.SetType(PacketTypeData)

	datapkt := DataPacket(pkt)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad data packet creation"))
	}

	return datapkt
}

func (p DataPacket) Valid() bool {
	return len(p) >= DataPacketHeaderLength && Packet(p).Type() == PacketTypeData
}

func (p DataPacket) IP() net.IP {
	if !p.Valid() {
		return nil
	}

	return net.IPv4(p[PacketTypeLength], p[PacketTypeLength+1], p[PacketTypeLength+2], p[PacketTypeLength+3])
}

func (p DataPacket) Data() []byte {
	if !p.Valid() {
		return nil
	}

	return p[DataPacketHeaderLength:]
}

func (p DataPacket) SetIP(ip net.IP) {
	copy(p[PacketTypeLength:PacketTypeLength+PacketIPv4Length], ip.To4())
}

func (p DataPacket) SetData(data []byte) {
	copy(p[DataPacketHeaderLength:], data)
}
