package packet

import (
	"fmt"

	"github.com/google/uuid"
)

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
