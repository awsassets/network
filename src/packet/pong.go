package packet

import (
	"fmt"

	"github.com/google/uuid"
)

/*
The pong packet is used to respond to a ping packet.
The pong packet provides to bits of data, the first being
that the route to the node is infact VALID and the second being
that the node DOES NOT have an encryption key for the NODE which SENT
the PING packet.

The ID is the SAME ID from the PING packet which caused this packet to
be issued. This implementation uses a UUID (which is 16 bytes).

The structure looks like this.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      3        |                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                       16 bytes of ID                          :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :               |
    +-+-+-+-+-+-+-+-+


If the packet is a TCP packet then there are 2 extra bytes in front
of this which deonte the total data left in the packet.
Like this.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  BE uint16 remaining length   |       3       |               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                        16 bytes of ID                         :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	:                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

func (c *PacketConstructor) MakePongPacket(id uuid.UUID) PongPacket {
	pkt := Packet(c.slice(PongPacketLength))

	pkt.SetType(PacketTypePong)

	pong := PongPacket(pkt)

	pong.SetID(id)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad pong packet creation"))
	}

	return pong
}

func (p PongPacket) Valid() bool {
	return len(p) == PongPacketLength && Packet(p).Type() == PacketTypePong
}

func (p PongPacket) ID() uuid.UUID {
	if !p.Valid() {
		return uuid.UUID{}
	}

	id, _ := uuid.FromBytes(p[PacketTypeLength : PacketTypeLength+PacketIdLength])

	return id
}

func (p PongPacket) SetID(id uuid.UUID) {
	data, _ := id.MarshalBinary()
	copy(p[PacketTypeLength:PacketTypeLength+PacketIdLength], data)
}
