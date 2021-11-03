package conn_store

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/disembark/network/src/loadbalancer"
	"github.com/disembark/network/src/packet"

	node_store "github.com/disembark/network/src/store/node"

	"github.com/sirupsen/logrus"
)

type Store struct {
	mp        *sync.Map
	nodes     *node_store.Store
	udpConnLb *loadbalancer.LoadBalancer
}

func New(nodes *node_store.Store, lb *loadbalancer.LoadBalancer) *Store {
	s := &Store{
		mp:        &sync.Map{},
		nodes:     nodes,
		udpConnLb: lb,
	}

	go s.runner()

	return s
}

type Conn struct {
	name string
	ip   string

	ctx    context.Context
	cancel context.CancelFunc

	udpConnLb *loadbalancer.LoadBalancer

	udpAddr *net.UDPAddr
	connTcp *net.TCPConn

	lastPing    time.Time
	lastUdpPing time.Time

	lastWarnTCP time.Time
	lastWarnUDP time.Time

	deleted bool
}

func (c *Store) Stop(ip string) {
	if v, ok := c.mp.LoadAndDelete(ip); ok {
		conn := v.(*Conn)
		conn.deleted = true

		logrus.Debugf("cleaning up connection: %s - %s", conn.name, conn.ip)

		conn.cancel()
	}
}

func (c *Store) Get(ip string) *Conn {
	if v, ok := c.mp.Load(ip); ok {
		return v.(*Conn)
	}

	return nil
}

func (c *Store) New(ip string) *Conn {
	node, ok := c.nodes.GetNode(ip)
	if !ok {
		return nil
	}

	if !node.Relay {
		return nil
	}

	conn := &Conn{
		ip:        node.IP,
		name:      node.Name,
		lastPing:  time.Now(),
		udpConnLb: c.udpConnLb,
	}

	if v, ok := c.mp.LoadOrStore(node.IP, conn); ok {
		return v.(*Conn)
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn.ctx = ctx
	conn.cancel = cancel

	return conn
}

func (c *Store) runner() {
	tick := time.NewTicker(time.Minute * 5)
	for range tick.C {
		c.cleanup()
	}
}

func (c *Store) cleanup() {
	c.mp.Range(func(key, value interface{}) bool {
		conn := value.(*Conn)

		if conn.lastPing.Before(time.Now().Add(-time.Minute * 10)) {
			c.Stop(conn.ip)
		}

		return true
	})
}

func (c *Conn) RegisterPing(conn *net.TCPConn) {
	c.lastPing = time.Now()
	c.connTcp = conn
}

func (c *Conn) StopTCP() {
	c.connTcp = nil
}

func (c *Conn) RegisterPingUDP(addr *net.UDPAddr) {
	c.lastPing = time.Now()
	c.lastUdpPing = time.Now()

	c.udpAddr = addr
}

func (c *Conn) udpValid() bool {
	return c.udpAddr != nil && c.lastUdpPing.Add(time.Minute*5).After(time.Now())
}

func (c *Conn) WriteUDP(pkt packet.TcpPacket) error {
	if !c.udpValid() {
		if c.connTcp == nil {
			// fallback to udp if we cannot use tcp
			if c.lastWarnUDP.Before(time.Now().Add(-time.Second * 5)) {
				logrus.Warnf("both udp and tcp seem to be down for node: %s - %s", c.name, c.ip)
				c.lastWarnUDP = time.Now()
			} else {
				logrus.Debugf("both udp and tcp seem to be down for node:  %s - %s", c.name, c.ip)
			}
			return fmt.Errorf("unable to route")
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
	_, err := c.udpConnLb.GetNext().(*net.UDPConn).WriteToUDP(pkt.ToPacket(), c.udpAddr)

	return err
}

func (c *Conn) WriteTCP(pkt packet.TcpPacket) error {
	if c.connTcp == nil {
		if !c.udpValid() {
			// fallback to udp if we cannot use tcp
			if c.lastWarnTCP.Before(time.Now().Add(-time.Second * 5)) {
				logrus.Warnf("both udp and tcp seem to be down for node: %s - %s", c.name, c.ip)
				c.lastWarnTCP = time.Now()
			} else {
				logrus.Debugf("both udp and tcp seem to be down for node:  %s - %s", c.name, c.ip)
			}
			return fmt.Errorf("unable to route")
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
