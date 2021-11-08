package packet

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/disembark/network/src/netconn"
)

type PacketConstructor struct {
	buf  []byte
	size uint16
}

type RelayPacketConstructor struct {
	Relay    *PacketConstructor
	Standard *PacketConstructor
}

func NewRelayConstructor() *RelayPacketConstructor {
	// we want to make sure the network packet data lands where it is going to be in the final data packet.
	// to do this we must look at where the data should be.
	// There is a header for the datapacket which needs to be offset here.
	// we need to check if this changes ever so that we can update the underlying buffer with the new ip to avoid copying data
	relayPc := NewConstructor()
	stdPc := NewConstructorWithBuffer(relayPc.Buffer()[RelayPacketHeaderLength-TCPHeaderLength:])

	return &RelayPacketConstructor{
		Relay:    relayPc,
		Standard: stdPc,
	}
}

type (
	UdpPacket []byte
	TcpPacket []byte
)

func (t TcpPacket) Size() uint16 {
	return binary.BigEndian.Uint16(t[:TCPHeaderLength])
}

func (t TcpPacket) ToPacket() Packet {
	return Packet(t[TCPHeaderLength:])
}

func (t UdpPacket) ToPacket() Packet {
	return Packet(t)
}

func NewConstructor() *PacketConstructor {
	return &PacketConstructor{
		buf: make([]byte, (MaxContentSize+TCPHeaderLength)*3), // big enough buffer for all packet sizes
	}
}

func NewConstructorWithBuffer(buf []byte) *PacketConstructor {
	return &PacketConstructor{
		buf: buf,
	}
}

func (t *PacketConstructor) Size() uint16 {
	return binary.BigEndian.Uint16(t.buf[:TCPHeaderLength])
}

func (p *PacketConstructor) Buffer() []byte {
	return p.buf[TCPHeaderLength:]
}

func (p *PacketConstructor) slice(size int) []byte {
	if size > len(p.buf)-TCPHeaderLength {
		panic(fmt.Sprintf("invalid packet size: %d max %d", size, len(p.buf)-TCPHeaderLength))
	}

	p.SetSize(uint16(size))

	return p.buf[TCPHeaderLength : size+TCPHeaderLength]
}

func (p *PacketConstructor) ToUDP() UdpPacket {
	return p.buf[TCPHeaderLength : p.size+TCPHeaderLength]
}

func (p *PacketConstructor) ToTCP() TcpPacket {
	return p.buf[:p.size+TCPHeaderLength]
}

func (p *PacketConstructor) ToPacket() Packet {
	return p.ToUDP().ToPacket()
}

func (p *PacketConstructor) SetSize(size uint16) {
	binary.BigEndian.PutUint16(p.buf[:TCPHeaderLength], uint16(size))
	p.size = size
}

func (p *PacketConstructor) ReadTCP(read io.Reader) error {
	_, err := io.ReadFull(read, p.buf[:TCPHeaderLength])
	if err == io.EOF {
		_, err = io.ReadFull(read, p.buf[:TCPHeaderLength])
	}
	if err != nil {
		return err
	}

	size := int(binary.BigEndian.Uint16(p.buf[:TCPHeaderLength]))
	if size > len(p.buf)-TCPHeaderLength {
		return fmt.Errorf("bad packet size read: %d", size)
	}

	buf := p.slice(size)
	_, err = io.ReadFull(read, buf)
	if err == io.EOF {
		_, err = io.ReadFull(read, buf)
	}

	return err
}

func (p *PacketConstructor) ReadUDP(read netconn.UDPConn) (*net.UDPAddr, error) {
	n, addr, err := read.ReadFromUDP(p.buf[TCPHeaderLength:])

	p.SetSize(uint16(n))

	return addr, err
}
