package packet

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type PacketConstructor struct {
	buf  []byte
	size int
}

type (
	UdpPacket []byte
	TcpPacket []byte
)

func (t TcpPacket) Size() uint16 {
	return binary.BigEndian.Uint16(t[:2])
}

func (t TcpPacket) ToPacket() Packet {
	return Packet(t[2:])
}

func (t UdpPacket) ToPacket() Packet {
	return Packet(t)
}

func NewConstructor() *PacketConstructor {
	return &PacketConstructor{
		buf: make([]byte, MaxPacketSize+2), // big enough buffer for all packet sizes
	}
}

func (p *PacketConstructor) Buffer() []byte {
	return p.buf[2:]
}

func (p *PacketConstructor) slice(size int) []byte {
	if size > MaxPacketSize {
		panic(fmt.Sprintf("invalid packet size: %d max %d", size, MaxPacketSize))
	}

	binary.BigEndian.PutUint16(p.buf[:2], uint16(size))
	p.size = size

	return p.buf[2 : size+2]
}

func (p *PacketConstructor) ToUDP() UdpPacket {
	return p.buf[2 : p.size+2]
}

func (p *PacketConstructor) ToTCP() TcpPacket {
	return p.buf[:p.size+2]
}

func (p *PacketConstructor) ToPacket() Packet {
	return p.ToUDP().ToPacket()
}

func (p *PacketConstructor) ReadTCP(read io.Reader) error {
	_, err := io.ReadFull(read, p.buf[:2])
	if err == io.EOF {
		_, err = io.ReadFull(read, p.buf[:2])
	}
	if err != nil {
		return err
	}

	size := int(binary.BigEndian.Uint16(p.buf[:2]))
	if size > MaxPacketSize {
		return fmt.Errorf("bad packet size read: %d", size)
	}

	buf := p.slice(size)
	_, err = io.ReadFull(read, buf)
	if err == io.EOF {
		_, err = io.ReadFull(read, buf)
	}

	return err
}

func (p *PacketConstructor) ReadUDP(read *net.UDPConn) (*net.UDPAddr, error) {
	n, addr, err := read.ReadFromUDP(p.buf[2:])
	p.size = n
	binary.BigEndian.PutUint16(p.buf[:2], uint16(n))
	return addr, err
}
