package packet

import (
	"github.com/google/uuid"
)

func (c *PacketConstructor) MakePongAesPacket(id uuid.UUID, data []byte, hmac []byte) PongAesPacket {
	pkt := Packet(c.slice(PongAesPacketLength))

	pkt.SetType(PacketTypePongAes)

	pong := PongAesPacket(pkt)

	pong.SetID(id)
	pong.SetData(data)
	pong.SetHmac(hmac)

	if !c.ToPacket().Valid() {
		panic("bad pong aes packet creation")
	}

	return pong
}

func (p PongAesPacket) Valid() bool {
	return len(p) == PongAesPacketLength && Packet(p).Type() == PacketTypePongAes
}

func (p PongAesPacket) ID() uuid.UUID {
	if !p.Valid() {
		return uuid.UUID{}
	}

	id, _ := uuid.FromBytes(p[1 : 1+16])

	return id
}

func (p PongAesPacket) SetID(id uuid.UUID) {
	copy(p[1:1+16], id[:])
}

func (p PongAesPacket) Data() []byte {
	if !p.Valid() {
		return nil
	}

	return p[1+16 : 1+16+32]
}

func (p PongAesPacket) SetData(data []byte) {
	if len(data) != 32 {
		panic("bad data length required 32 bytes")
	}

	copy(p[1+16:1+16+32], data)
}

func (p PongAesPacket) Hmac() []byte {
	if !p.Valid() {
		return nil
	}

	return p[1+16+32 : 1+16+32+64]
}

func (p PongAesPacket) SetHmac(hmac []byte) {
	if len(hmac) != 64 {
		panic("bad data length required 32 bytes")
	}

	copy(p[1+16+32:1+16+32+64], hmac)
}
