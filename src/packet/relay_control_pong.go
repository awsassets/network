package packet

import (
	"fmt"

	"github.com/google/uuid"
)

/*
The relay control pong packet is used to respond to relay control
ping packets. These packets ARE ONLY USED between relay servers and
relay clients.

The ID is the SAME ID from the PING packet which caused this packet to
be issued. This implementation uses a UUID (which is 16 bytes).

The structure looks like this.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      8        |                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                       16 bytes of ID                          :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :               |
    +-+-+-+-+-+-+-+-+


If the packet is a TCP packet then there are 2 extra bytes in front
of this which deonte the total data left in the packet.
Like this.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  BE uint16 remaining length   |       8       |               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                       16 bytes of ID                          :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

func (c *PacketConstructor) MakeRelayControlPongPacket(id uuid.UUID) RelayControlPongPacket {
	pkt := Packet(c.slice(RelayControlPongPacketLength))

	pkt.SetType(PacketTypeRelayControlPong)

	pong := RelayControlPongPacket(pkt)

	pong.SetID(id)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad pong packet creation"))
	}

	return pong
}

func (p RelayControlPongPacket) Valid() bool {
	return len(p) == RelayControlPongPacketLength && Packet(p).Type() == PacketTypeRelayControlPong
}

func (p RelayControlPongPacket) ID() uuid.UUID {
	if !p.Valid() {
		return uuid.UUID{}
	}

	id, _ := uuid.FromBytes(p[PacketTypeLength : PacketTypeLength+PacketIdLength])

	return id
}

func (p RelayControlPongPacket) SetID(id uuid.UUID) {
	copy(p[PacketTypeLength:PacketTypeLength+PacketIdLength], id[:])
}
