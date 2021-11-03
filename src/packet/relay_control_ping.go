package packet

import (
	"fmt"

	"github.com/google/uuid"
)

func (c *PacketConstructor) MakeRelayControlPingPacket(id uuid.UUID, token []byte) RelayControlPingPacket {
	pkt := Packet(c.slice(RelayControlPingPacketLength))

	pkt.SetType(PacketTypeRelayControlPing)

	pong := RelayControlPingPacket(pkt)

	pong.SetID(id)
	pong.SetToken(token)

	if !c.ToPacket().Valid() {
		panic(fmt.Errorf("bad relay control ping packet creation"))
	}

	return pong
}

func (p RelayControlPingPacket) Valid() bool {
	return len(p) == RelayControlPingPacketLength && Packet(p).Type() == PacketTypeRelayControlPing
}

func (p RelayControlPingPacket) ID() uuid.UUID {
	if !p.Valid() {
		return uuid.UUID{}
	}

	id, _ := uuid.FromBytes(p[PacketTypeLength : PacketTypeLength+PacketIdLength])

	return id
}

func (p RelayControlPingPacket) SetID(id uuid.UUID) {
	copy(p[PacketTypeLength:PacketTypeLength+PacketIdLength], id[:])
}

func (p RelayControlPingPacket) Token() []byte {
	if !p.Valid() {
		return nil
	}

	return p[PacketTypeLength+PacketIdLength : PacketTypeLength+PacketIdLength+PacketRelayControlPingTokenLength]
}

func (p RelayControlPingPacket) SetToken(token []byte) {
	if len(token) != PacketRelayControlPingTokenLength {
		panic(fmt.Errorf("invalid token length %d", PacketRelayControlPingTokenLength))
	}

	copy(p[PacketTypeLength+PacketIdLength:PacketTypeLength+PacketIdLength+PacketRelayControlPingTokenLength], token)
}
