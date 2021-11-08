package netutil

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/disembark/network/src/network"
	"github.com/disembark/network/src/packet"
	"github.com/go-ping/ping"
	"github.com/songgao/water/waterutil"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_GetAddr(t *testing.T) {
	src, dst, proto := GetAddr(nil)

	assert.Equal(t, "", src, "Invalid packet")
	assert.Equal(t, "", dst, "Invalid packet")
	assert.Equal(t, waterutil.IPProtocol(0), proto, "Invalid packet")

	tun := network.CreateTun()
	defer func() {
		_ = tun.Stop()
	}()

	_, err := tun.ConfigureDNS()
	assert.ErrorIs(t, err, nil, "Dns is configured")

	tun.Name()
	tun.GetNext()
	tun.GetIndex(0)

	tun.SetIP("10.10.0.1")

	for _, v := range tun.GetRaws() {
		go func(dev network.Device) {
			buf := make([]byte, packet.MTU)
			for {
				n, err := dev.Read(buf)
				if err != nil {
					return
				}

				pkt := buf[:n]

				src, dest, proto := GetAddr(pkt)
				if src == "" || dest == "" {
					continue
				}

				if proto == waterutil.UDP {
					if RemovePort(dest) == "10.10.0.2" {
						// we need to respond to this ping packet :)
						destAddr := waterutil.IPv4Destination(pkt)
						srcAddr := waterutil.IPv4Source(pkt)

						destPort := waterutil.IPv4DestinationPort(pkt)
						srcPort := waterutil.IPv4SourcePort(pkt)

						waterutil.SetIPv4Destination(pkt, srcAddr)
						waterutil.SetIPv4Source(pkt, destAddr)
						waterutil.SetIPv4DestinationPort(pkt, srcPort)
						waterutil.SetIPv4SourcePort(pkt, destPort)

						_, err = dev.Write(pkt)
						assert.ErrorIs(t, err, nil, "no errors when writing")
					}
				} else if proto == waterutil.ICMP {
					destAddr := waterutil.IPv4Destination(pkt)
					srcAddr := waterutil.IPv4Source(pkt)
					waterutil.SetIPv4Destination(pkt, srcAddr)
					waterutil.SetIPv4Source(pkt, destAddr)

					_, err = dev.Write(pkt)
					assert.ErrorIs(t, err, nil, "no errors when writing")
				}
			}
		}(v)
	}

	conn, err := net.Dial("udp", "10.10.0.2:55555")
	assert.ErrorIs(t, err, nil, "No error when dialing udp conn")

	buf := make([]byte, packet.MTU)

	n := copy(buf, []byte("testing udp packets"))

	srcPkt := buf[:n]

	_, err = conn.Write(buf[:n])
	assert.ErrorIs(t, err, nil, "No error when writing packet")

	buf2 := make([]byte, packet.MTU)
	n, err = conn.Read(buf2)
	assert.ErrorIs(t, err, nil, "No error when reading packet")

	pkt := buf2[:n]

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	assert.Equal(t, hash(srcPkt), hash(pkt), "The udp ping pong doesnt drop any data")

	pinger, err := ping.NewPinger("10.10.0.2")
	assert.ErrorIs(t, err, nil, "no errors when sending pings")
	pinger.Count = 3

	err = pinger.Run()
	assert.ErrorIs(t, err, nil, "no errors when sending pings")

	assert.Equal(t, float64(0), pinger.Statistics().PacketLoss, "No packets were dropped")
}

func Test_RemovePort(t *testing.T) {
	assert.Equal(t, "127.0.0.1", RemovePort("127.0.0.1:6766"), "Removed port")
	assert.Equal(t, "127.0.0.1", RemovePort("127.0.0.1"), "Removed port")
}
