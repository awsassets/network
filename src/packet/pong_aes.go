package packet

import (
	"fmt"

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
		panic(fmt.Errorf("bad pong aes packet creation"))
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

	id, _ := uuid.FromBytes(p[PacketTypeLength : PacketTypeLength+PacketIdLength])

	return id
}

func (p PongAesPacket) SetID(id uuid.UUID) {
	data, _ := id.MarshalBinary()
	copy(p[PacketTypeLength:PacketTypeLength+PacketIdLength], data)
}

func (p PongAesPacket) Data() []byte {
	if !p.Valid() {
		return nil
	}

	return p[PacketTypeLength+PacketIdLength : PacketTypeLength+PacketIdLength+PacketPongAesDataLength]
}

func (p PongAesPacket) SetData(data []byte) {
	if len(data) != PacketPongAesDataLength {
		panic(fmt.Errorf("bad data length required %d bytes", PacketPongAesDataLength))
	}

	copy(p[PacketTypeLength+PacketIdLength:PacketTypeLength+PacketIdLength+PacketPongAesDataLength], data)
}

func (p PongAesPacket) Hmac() []byte {
	if !p.Valid() {
		return nil
	}

	return p[PacketTypeLength+PacketIdLength+PacketPongAesDataLength : PacketTypeLength+PacketIdLength+PacketPongAesDataLength+PacketPongAesHmacLength]
}

func (p PongAesPacket) SetHmac(hmac []byte) {
	if len(hmac) != PacketPongAesHmacLength {
		panic(fmt.Errorf("bad data length required %d bytes", PacketPongAesHmacLength))
	}

	copy(p[PacketTypeLength+PacketIdLength+PacketPongAesDataLength:PacketTypeLength+PacketIdLength+PacketPongAesDataLength+PacketPongAesHmacLength], hmac)
}
