package packet

type PacketType byte

const (
	_ PacketType = iota
	PacketTypeData
	PacketTypePing
	PacketTypePong
	PacketTypePongAes
	PacketTypeExchange
)

const (
	MTU           = 65000
	MaxPacketSize = MTU + 64
)

type (
	Packet         []byte
	DataPacket     Packet
	PingPacket     Packet
	PongPacket     Packet
	PongAesPacket  Packet
	ExchangePacket Packet
)

const (
	PingPacketLength           = 1 + 4 + 16
	PongPacketLength           = 1 + 16
	PongAesPacketLength        = 1 + 16 + 32 + 64
	ExchangePacketHeaderLength = 1 + 4
	DataPacketHeaderLength     = 1 + 4

	TCPHeader = 2
)

func (p Packet) Type() PacketType {
	if len(p) == 0 {
		return 0
	}

	return PacketType(p[0])
}

func (p Packet) Valid() bool {
	switch p.Type() {
	case PacketTypeData:
		return DataPacket(p).Valid()
	case PacketTypePing:
		return PingPacket(p).Valid()
	case PacketTypePong:
		return PongPacket(p).Valid()
	case PacketTypePongAes:
		return PongAesPacket(p).Valid()
	case PacketTypeExchange:
		return ExchangePacket(p).Valid()
	}

	return false
}

func (p Packet) SetType(t PacketType) {
	if len(p) == 0 {
		return
	}

	p[0] = byte(t)
}

func (p Packet) Copy() Packet {
	n := make(Packet, len(p))
	copy(n, p)
	return n
}

func (p Packet) CopyTo(n []byte) Packet {
	copy(n, p)
	return n
}
