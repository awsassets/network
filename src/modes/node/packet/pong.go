package packet

import (
	"github.com/google/uuid"
)

func (c *PacketConstructor) MakePongPacket(id uuid.UUID) PongPacket {
	pkt := Packet(c.slice(PongPacketLength))

	pkt.SetType(PacketTypePong)

	pong := PongPacket(pkt)

	pong.SetID(id)

	if !c.ToPacket().Valid() {
		panic("bad pong packet creation")
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

	id, _ := uuid.FromBytes(p[1 : 1+16])

	return id
}

func (p PongPacket) SetID(id uuid.UUID) {
	copy(p[1:1+16], id[:])
}
