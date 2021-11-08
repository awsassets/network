package conn_store

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/disembark/network/src/loadbalancer"
	"github.com/disembark/network/src/netconn"
	"github.com/disembark/network/src/packet"

	"github.com/sirupsen/logrus"
)

var ErrNoRoute = fmt.Errorf("unable to route")

type Conn interface {
	RegisterPing(conn net.Conn)
	StopTCP()
	RegisterPingUDP(addr *net.UDPAddr)
	WriteUDP(pkt packet.TcpPacket) error
	WriteTCP(pkt packet.TcpPacket) error
}

type MockConnInstance struct {
	RegisterPingFunc    func(conn net.Conn)
	StopTCPFunc         func()
	RegisterPingUDPFunc func(addr *net.UDPAddr)
	WriteUDPFunc        func(pkt packet.TcpPacket) error
	WriteTCPFunc        func(pkt packet.TcpPacket) error
}

func (m MockConnInstance) RegisterPing(conn net.Conn) {
	m.RegisterPingFunc(conn)
}

func (m MockConnInstance) StopTCP() {
	m.StopTCPFunc()
}

func (m MockConnInstance) WriteUDP(pkt packet.TcpPacket) error {
	return m.WriteUDPFunc(pkt)
}

func (m MockConnInstance) WriteTCP(pkt packet.TcpPacket) error {
	return m.WriteTCPFunc(pkt)
}

type ConnInstance struct {
	name string
	ip   string

	ctx    context.Context
	cancel context.CancelFunc

	udpConnLb loadbalancer.LoadBalancer

	udpAddr *net.UDPAddr
	connTcp net.Conn

	lastPing    time.Time
	lastUdpPing time.Time

	lastWarnTCP time.Time
	lastWarnUDP time.Time

	forceUDP bool
	forceTCP bool

	deleted bool
}

func (c *ConnInstance) RegisterPing(conn net.Conn) {
	c.lastPing = time.Now()
	c.connTcp = conn
}

func (c *ConnInstance) StopTCP() {
	c.connTcp = nil
}

func (c *ConnInstance) RegisterPingUDP(addr *net.UDPAddr) {
	c.lastPing = time.Now()
	c.lastUdpPing = time.Now()

	c.udpAddr = addr
}

func (c *ConnInstance) udpValid() bool {
	return c.udpAddr != nil && c.lastUdpPing.Add(time.Minute*5).After(time.Now())
}

func (c *ConnInstance) WriteUDP(pkt packet.TcpPacket) error {
	if !c.udpValid() || c.forceTCP {
		if c.connTcp == nil || c.forceUDP {
			// fallback to udp if we cannot use tcp
			if c.lastWarnUDP.Before(time.Now().Add(-time.Second * 5)) {
				logrus.Warnf("both udp and tcp seem to be down for node: %s - %s", c.name, c.ip)
				c.lastWarnUDP = time.Now()
			} else {
				logrus.Debugf("both udp and tcp seem to be down for node:  %s - %s", c.name, c.ip)
			}
			return ErrNoRoute
		}

		// fallback to udp if we cannot use tcp
		if c.lastWarnUDP.Before(time.Now().Add(-time.Second * 5)) {
			logrus.Warnf("using tcp since udp seems to be down on node: %s - %s", c.name, c.ip)
			c.lastWarnUDP = time.Now()
		} else {
			logrus.Debugf("using tcp since udp seems to be down on node: %s - %s", c.name, c.ip)
		}

		return c.WriteTCP(pkt)
	}

	if len(pkt) > packet.MaxContentSize {
		panic(fmt.Errorf("bad packet length %d", len(pkt)))
	}

	logrus.Debugf("writing udp packet to %s - %s", c.name, c.ip)
	_, err := c.udpConnLb.GetNext().(netconn.UDPConn).WriteToUDP(pkt.ToPacket(), c.udpAddr)

	return err
}

func (c *ConnInstance) WriteTCP(pkt packet.TcpPacket) error {
	if c.connTcp == nil || c.forceUDP {
		if !c.udpValid() || c.forceTCP {
			// fallback to udp if we cannot use tcp
			if c.lastWarnTCP.Before(time.Now().Add(-time.Second * 5)) {
				logrus.Warnf("both udp and tcp seem to be down for node: %s - %s", c.name, c.ip)
				c.lastWarnTCP = time.Now()
			} else {
				logrus.Debugf("both udp and tcp seem to be down for node:  %s - %s", c.name, c.ip)
			}
			return ErrNoRoute
		}

		// fallback to udp if we cannot use tcp
		if c.lastWarnTCP.Before(time.Now().Add(-time.Second * 5)) {
			logrus.Warnf("using udp since tcp seems to be down on node: %s - %s", c.name, c.ip)
			c.lastWarnTCP = time.Now()
		} else {
			logrus.Debugf("using udp since tcp seems to be down on node: %s - %s", c.name, c.ip)
		}

		return c.WriteUDP(pkt)
	}

	if len(pkt) > packet.MaxContentSize {
		panic(fmt.Errorf("bad packet length %d", len(pkt)))
	}

	logrus.Debugf("writing tcp packet to %s - %s", c.name, c.ip)
	_, err := c.connTcp.Write(pkt)

	return err
}
