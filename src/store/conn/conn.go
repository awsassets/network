package conn_store

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/disembark/network/src/loadbalancer"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/packet"
	"github.com/disembark/network/src/utils"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"

	aes_store "github.com/disembark/network/src/store/aes"
	node_store "github.com/disembark/network/src/store/node"
)

type Store struct {
	mp    *sync.Map
	nodes *node_store.Store
	aes   *aes_store.Store
	ourIP *string
}

func New(nodes *node_store.Store, ourIP *string) *Store {
	s := &Store{
		mp: &sync.Map{},

		nodes: nodes,
		aes:   aes_store.New(),
		ourIP: ourIP,
	}

	go s.runner()

	return s
}

type Conn struct {
	name   string
	ip     string
	ctx    context.Context
	cancel context.CancelFunc

	connUdp *loadbalancer.LoadBalancer
	connTcp *loadbalancer.LoadBalancer

	nodes *node_store.Store
	aes   *aes_store.Store
	ourIP *string

	deleted  bool
	lastUsed time.Time

	lastWarnTCP time.Time
	lastWarnUDP time.Time
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

	conn := &Conn{
		ip:       node.IP,
		name:     node.Name,
		nodes:    c.nodes,
		aes:      c.aes,
		ourIP:    c.ourIP,
		lastUsed: time.Now(),
	}

	if v, ok := c.mp.LoadOrStore(node.IP, conn); ok {
		return v.(*Conn)
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn.ctx = ctx
	conn.cancel = cancel

	c.aes.GetOrNew(node.Name)

	go func() {
		conn.manageUDP()
		c.Stop(conn.ip)
	}()

	go func() {
		conn.manageTCP()
		c.Stop(conn.ip)
	}()

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

		if conn.lastUsed.Before(time.Now().Add(-time.Minute * 10)) {
			c.Stop(conn.ip)
		}

		return true
	})
}

func (c *Conn) manageTCP() {
	first := true
	pc := packet.NewConstructor()
	for {
		if !first {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(time.Second):
			}
		} else {
			first = false
		}
		if c.ctx.Err() != nil {
			return
		}
		func() {
			node, ok := c.nodes.GetNode(c.ip)
			if !ok || node.Name != c.name {
				return
			}

			var conns []*net.TCPConn
			var err error
			for _, ip := range node.AdvertiseAddresses {
				conns, err = netutil.DialTCP("", ip)
				if err != nil {
					continue
				}
				break
			}

			if len(conns) == 0 {
				logrus.Warnf("cannot find tcp route to node: %s %s", c.ip, err.Error())
				return
			}

			defer func() {
				for _, v := range conns {
					_ = v.Close()
				}
			}()

			pongCh := make(chan packet.Packet, 1)
			lCtx, lCancel := context.WithCancel(c.ctx)

			defer lCancel()
			defer close(pongCh)

			c.connTcp = loadbalancer.NewLoadBalancer()
			for _, v := range conns {
				c.connTcp.AddItem(v)
				go func(conn *net.TCPConn) {
					defer lCancel()

					pc := packet.NewConstructor()
					for {
						err := pc.ReadTCP(conn)
						if err != nil {
							return
						}

						pkt := pc.ToPacket()
						if !pkt.Valid() {
							logrus.Warn("bad packet from tcp read")
							continue
						}

						switch pkt.Type() {
						case packet.PacketTypePong, packet.PacketTypePongAes:
							pongCh <- pkt.Copy()
						}
					}
				}(v)
			}

			id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
			if node.Relay {
				pc.MakeRelayPingPacket(id, net.ParseIP(*c.ourIP), net.ParseIP(node.IP))
			} else {
				pc.MakePingPacket(id, net.ParseIP(*c.ourIP))
			}

			if _, err := c.connTcp.GetNext().(*net.TCPConn).Write(pc.ToTCP()); err != nil {
				logrus.Error("failed to write: ", err)
				return
			}

			logrus.Debugf("sending tcp ping to %s - %s - %s", c.name, c.ip, id.String())

			timeout := time.After(time.Second * 5)
			aesKeyExchanged := false
			timedout := false

		outer:
			for {
				select {
				case pkt, ok := <-pongCh:
					if !ok {
						timedout = true
						break outer
					}
					switch pkt.Type() {
					case packet.PacketTypePong:
						pkt := packet.PongPacket(pkt)
						if pkt.ID() != id {
							continue
						}
					case packet.PacketTypePongAes:
						pkt := packet.PongAesPacket(pkt)
						hash := hmac.New(sha3.New512, c.Aes().KeyRaw())
						_, _ = hash.Write(pkt.Data())

						hMAC := hash.Sum(nil)

						aesKeyExchanged = hmac.Equal(hMAC, pkt.Hmac())
					}
					break outer
				case <-timeout:
					timedout = true
					break outer
				}
			}

			if timedout {
				return
			}

			if !aesKeyExchanged {
				// the other node does not have our aes key.
				// we must give it to them.
				b, _ := pem.Decode(utils.S2B(node.PublicKey))
				cert, _ := x509.ParseCertificate(b.Bytes)
				public := ecies.ImportECDSAPublic(cert.PublicKey.(*ecdsa.PublicKey))
				encrypted, err := ecies.Encrypt(rand.Reader, public, c.Aes().KeyRaw(), nil, nil)
				if err != nil {
					logrus.Fatal("failed to encrypt data: ", err)
				}

				if node.Relay {
					pc.MakeRelayExchangePacket(encrypted, net.ParseIP(*c.ourIP), net.ParseIP(node.IP))
				} else {
					pc.MakeExchangePacket(encrypted, net.ParseIP(*c.ourIP))
				}

				if err := c.WriteTCP(pc.ToTCP()); err != nil {
					logrus.Error("failed to write: ", err)
				}
			}

			logrus.Debugf("tcp is okay for %s - %s", c.name, c.ip)

			for {
				select {
				case <-lCtx.Done():
					return
				case <-pongCh:
				}
			}
		}()
	}
}

func (c *Conn) manageUDP() {
	tick := time.NewTicker(time.Second * 5)
	defer tick.Stop()
	pongCh := make(chan packet.Packet, 100)

	pc := packet.NewConstructor()
	first := true

	{
	start:
		node, ok := c.nodes.GetNode(c.ip)
		if !ok || node.Name != c.name {
			return
		}

		{
		ip:
			for _, ip := range node.AdvertiseAddresses {
				if c.connUdp != nil {
					for _, v := range c.connUdp.GetItems() {
						_ = v.(*net.UDPConn).Close()
					}
					c.connUdp = nil
				}

				{
				rerun:
					if !first {
						select {
						case <-pongCh:
						case <-tick.C:
						case <-c.ctx.Done():
							return
						}
					} else {
						first = false
						if c.ctx.Err() != nil {
							return
						}
					}

					node, ok := c.nodes.GetNode(c.ip)
					if !ok || node.Name != c.name {
						return
					}

					pings := map[string]string{}

					var lb *loadbalancer.LoadBalancer
					if c.connUdp != nil {
						lb = c.connUdp
					} else {
						lb = loadbalancer.NewLoadBalancer()

						conns, err := netutil.DialUDP("", ip)
						if err != nil {
							continue ip
						}
						for _, v := range conns {
							lb.AddItem(v)
							go func(conn *net.UDPConn) {
								pc := packet.NewConstructor()
								for {
									_, err := pc.ReadUDP(conn)
									if err != nil {
										return
									}

									pkt := pc.ToPacket()
									if !pkt.Valid() {
										logrus.Warn("bad packet from udp read")
										continue
									}

									switch pkt.Type() {
									case packet.PacketTypePong, packet.PacketTypePongAes:
										pongCh <- pkt.Copy()
									}
								}
							}(v)
						}
					}

					for i := 0; i < 5; i++ {
						id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)

						if node.Relay {
							pc.MakeRelayPingPacket(id, net.ParseIP(*c.ourIP), net.ParseIP(node.IP))
						} else {
							pc.MakePingPacket(id, net.ParseIP(*c.ourIP))
						}

						pings[id.String()] = ip

						if _, err := lb.GetNext().(*net.UDPConn).Write(pc.ToUDP()); err != nil {
							logrus.Error("failed to write: ", err)
						}

						logrus.Debugf("sending udp ping to %s - %s - %s", c.name, c.ip, id.String())
					}

					timeout := time.After(time.Second * 5)
					i := 0
					ips := make([]string, len(pings))
					aesKeyExchanged := false

				outer:
					for i < len(ips) {
						select {
						case pkt := <-pongCh:
							switch pkt.Type() {
							case packet.PacketTypePong:
								pkt := packet.PongPacket(pkt)
								if v, ok := pings[pkt.ID().String()]; ok {
									ips[i] = v
									i++
									delete(pings, pkt.ID().String())
								}
							case packet.PacketTypePongAes:
								pkt := packet.PongAesPacket(pkt)
								if v, ok := pings[pkt.ID().String()]; ok {
									ips[i] = v
									i++
									delete(pings, pkt.ID().String())

									hash := hmac.New(sha3.New512, c.Aes().KeyRaw())
									_, _ = hash.Write(pkt.Data())
									hMAC := hash.Sum(nil)
									aesKeyExchanged = hmac.Equal(hMAC, pkt.Hmac())
								}
							}
						case <-timeout:
							break outer
						}
						if len(pings) == 0 {
							break outer
						}
					}

					ips = ips[:i]

					if len(ips) == 0 {
						logrus.Warnf("cannot find route to node: %s", c.ip)

						continue ip
					}

					c.connUdp = lb

					if !aesKeyExchanged {
						// the other node does not have our aes key.
						// we must give it to them.
						b, _ := pem.Decode(utils.S2B(node.PublicKey))
						cert, _ := x509.ParseCertificate(b.Bytes)
						public := ecies.ImportECDSAPublic(cert.PublicKey.(*ecdsa.PublicKey))
						encrypted, err := ecies.Encrypt(rand.Reader, public, c.Aes().KeyRaw(), nil, nil)
						if err != nil {
							logrus.Fatal("failed to encrypt data: ", err)
						}

						if node.Relay {
							pc.MakeRelayExchangePacket(encrypted, net.ParseIP(*c.ourIP), net.ParseIP(node.IP))
						} else {
							pc.MakeExchangePacket(encrypted, net.ParseIP(*c.ourIP))
						}

						logrus.Debugf("sending udp exchange to %s - %s", c.name, c.ip)

						for i := 0; i < 5; i++ {
							_ = c.WriteUDP(pc.ToTCP())
						}
					}

					logrus.Debugf("udp is okay for %s - %s", c.name, c.ip)

					goto rerun
				}
			}
		}
		goto start
	}
}

func (c *Conn) Aes() *aes_store.Key {
	return c.aes.Get(c.name)
}

func (c *Conn) WriteUDP(pkt packet.TcpPacket) error {
	if c.connUdp == nil {
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
	_, err := c.connUdp.GetNext().(*net.UDPConn).Write(pkt.ToPacket())

	c.lastUsed = time.Now()
	c.aes.Revive(c.name)

	return err
}

func (c *Conn) WriteTCP(pkt packet.TcpPacket) error {
	if c.connTcp == nil {
		if c.connUdp == nil {
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
	_, err := c.connTcp.GetNext().(*net.TCPConn).Write(pkt)

	c.lastUsed = time.Now()
	c.aes.Revive(c.name)

	return err
}
