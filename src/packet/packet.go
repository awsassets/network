package packet

type PacketType byte

const (
	PacketTypeInvalid PacketType = iota
	PacketTypeData
	PacketTypePing
	PacketTypePong
	PacketTypePongAes
	PacketTypeExchange
	PacketTypeRelay

	// used to register nodes on relay servers
	PacketTypeRelayControlPing
	PacketTypeRelayControlPong
)

const (
	MTU            = 1420
	MaxContentSize = 1500
)

type (
	Packet         []byte
	DataPacket     Packet
	PingPacket     Packet
	PongPacket     Packet
	PongAesPacket  Packet
	ExchangePacket Packet
	RelayPacket    Packet

	RelayControlPingPacket Packet
	RelayControlPongPacket Packet
)

const (
	TCPHeaderLength = 2

	PacketTypeLength                  = 1
	PacketIPv4Length                  = 4
	PacketIdLength                    = 16
	PacketPongAesDataLength           = 32
	PacketPongAesHmacLength           = 64
	PacketRelayControlPingTokenLength = 32

	PingPacketLength           = PacketTypeLength + PacketIPv4Length + PacketIdLength
	PongPacketLength           = PacketTypeLength + PacketIdLength
	PongAesPacketLength        = PacketTypeLength + PacketIdLength + PacketPongAesDataLength + PacketPongAesHmacLength
	ExchangePacketHeaderLength = PacketTypeLength + PacketIPv4Length
	DataPacketHeaderLength     = PacketTypeLength + PacketIPv4Length
	RelayPacketHeaderLength    = PacketTypeLength + PacketIPv4Length

	RelayPingPacketLength           = RelayPacketHeaderLength + PingPacketLength
	RelayPongPacketLength           = RelayPacketHeaderLength + PongPacketLength
	RelayPongAesPacketLength        = RelayPacketHeaderLength + PongAesPacketLength
	RelayExchangePacketHeaderLength = RelayPacketHeaderLength + ExchangePacketHeaderLength
	RelayDataPacketHeaderLength     = RelayPacketHeaderLength + DataPacketHeaderLength

	RelayControlPingPacketLength = PacketTypeLength + PacketIdLength + PacketRelayControlPingTokenLength
	RelayControlPongPacketLength = PacketTypeLength + PacketIdLength
)

func (p Packet) Type() PacketType {
	if len(p) == 0 {
		return PacketTypeInvalid
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
	case PacketTypeRelay:
		return RelayPacket(p).Valid()
	case PacketTypeRelayControlPing:
		return RelayControlPingPacket(p).Valid()
	case PacketTypeRelayControlPong:
		return RelayControlPongPacket(p).Valid()
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
