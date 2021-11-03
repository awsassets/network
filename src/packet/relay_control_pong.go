package packet

import (
	"fmt"

	"github.com/google/uuid"
)

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
