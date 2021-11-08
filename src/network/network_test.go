//go:build linux && windows
// +build linux,windows

package network

import (
	"testing"

	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/packet"
	"github.com/go-ping/ping"
	"github.com/songgao/water/waterutil"
	"github.com/stretchr/testify/assert"
)

func Test_Linux(t *testing.T) {
	tun := createTun()
	defer tun.Stop()

	_, err := tun.ConfigureDNS()
	assert.ErrorIs(t, err, nil, "Dns is configured")

	tun.Name()
	tun.GetNext()
	tun.GetIndex(0)

	tun.SetIP("10.10.0.1")

	for _, v := range tun.GetRaws() {
		go func(dev Device) {
			buf := make([]byte, packet.MTU)
			for {
				n, err := dev.Read(buf)
				if err != nil {
					return
				}

				pkt := buf[:n]

				src, dest, proto := netutil.GetAddr(pkt)
				if src == "" || dest == "" {
					continue
				}

				if proto == waterutil.ICMP {
					if netutil.RemovePort(dest) == "10.10.0.2" {
						// we need to respond to this ping packet :)
						destAddr := waterutil.IPv4Destination(pkt)
						srcAddr := waterutil.IPv4Source(pkt)
						waterutil.SetIPv4Destination(pkt, srcAddr)
						waterutil.SetIPv4Source(pkt, destAddr)

						_, err = dev.Write(pkt)
						assert.ErrorIs(t, err, nil, "no errors when writing")
					}
				}
			}
		}(v)
	}

	pinger, err := ping.NewPinger("10.10.0.2")
	assert.ErrorIs(t, err, nil, "no errors when sending pings")
	pinger.Count = 3

	err = pinger.Run()
	assert.ErrorIs(t, err, nil, "no errors when sending pings")

	assert.Equal(t, float64(0), pinger.Statistics().PacketLoss, "No packets were dropped")

	tun.SetIP("10.10.0.3")
}
