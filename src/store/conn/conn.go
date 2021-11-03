package conn_store

import (
	"bufio"
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
	name         string
	ip           string
	selectedAddr string
	ctx          context.Context
	cancel       context.CancelFunc

	connUdp *net.UDPConn
	connTcp *net.TCPConn

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
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		logrus.Fatal("failed to make a connection: ", err)
	}

	conn.connUdp = udp
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
		if c.connTcp != nil {
			_ = c.connTcp.Close()
			c.connTcp = nil
		}

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

		node, ok := c.nodes.GetNode(c.ip)
		if !ok || node.Name != c.name {
			return
		}

		var conn *net.TCPConn
		for _, ip := range node.AdvertiseAddresses {
			addr, err := net.ResolveTCPAddr("tcp", ip)
			if err != nil {
				continue
			}
			conn, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				conn = nil
				continue
			}
			break
		}

		if conn == nil {
			logrus.Warnf("cannot find tcp route to node: %s", c.ip)
			continue
		}

		id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
		if node.Relay {
			pc.MakeRelayPingPacket(id, net.ParseIP(*c.ourIP), net.ParseIP(node.IP))
		} else {
			pc.MakePingPacket(id, net.ParseIP(*c.ourIP))
		}

		pkt := pc.ToTCP()

		if _, err := conn.Write(pkt); err != nil {
			logrus.Error("failed to write: ", err)
			continue
		}

		logrus.Debugf("sending tcp ping to %s - %s - %s", c.name, c.ip, id.String())

		pongCh := make(chan packet.Packet, 1)
		go func() {
			defer close(pongCh)

			pc := packet.NewConstructor()

			bconn := bufio.NewReader(conn)
			for {
				err := pc.ReadTCP(bconn)
				if err != nil {
					logrus.Error("bad tcp packet read: ", err)
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
		}()

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
			continue
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

			pkt := pc.ToTCP()

			if _, err := conn.Write(pkt); err != nil {
				logrus.Error("failed to write: ", err)
			}
		}

		c.connTcp = conn

		for range pongCh {
		}
	}
}

func (c *Conn) manageUDP() {
	tick := time.NewTicker(time.Second * 5)
	defer tick.Stop()
	defer c.connUdp.Close()

	pongCh := make(chan packet.Packet, 100)
	defer close(pongCh)
	go func() {
		pc := packet.NewConstructor()
		for {
			_, err := pc.ReadUDP(c.connUdp)
			if err != nil {
				if c.ctx.Err() == nil {
					logrus.Error(err)
				}
				return
			}
			pkt := pc.ToUDP().ToPacket()
			switch pkt.Type() {
			case packet.PacketTypePong, packet.PacketTypePongAes:
				pongCh <- pkt.Copy()
			}
		}
	}()

	pc := packet.NewConstructor()
	first := true
	for {
		if !first {
			select {
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

		for _, ip := range node.AdvertiseAddresses {
			addr, err := net.ResolveUDPAddr("udp", ip)
			if err != nil {
				continue
			}

			for i := 0; i < 5; i++ {
				id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)

				if node.Relay {
					pc.MakeRelayPingPacket(id, net.ParseIP(*c.ourIP), net.ParseIP(node.IP))
				} else {
					pc.MakePingPacket(id, net.ParseIP(*c.ourIP))
				}

				pkt := pc.ToUDP()

				pings[id.String()] = ip

				if _, err = c.connUdp.WriteToUDP(pkt, addr); err != nil {
					logrus.Error("failed to write: ", err)
				}

				logrus.Debugf("sending udp ping to %s - %s - %s", c.name, c.ip, id.String())
			}
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
		}

		ips = ips[:i]

		if len(ips) == 0 {
			logrus.Warnf("cannot find route to node: %s", c.ip)

			c.selectedAddr = ""

			continue
		}

		c.selectedAddr = ips[0]
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
	}
}

func (c *Conn) SelectedAddress() string {
	return c.selectedAddr
}

func (c *Conn) Aes() *aes_store.Key {
	return c.aes.Get(c.name)
}

func (c *Conn) WriteUDP(pkt packet.TcpPacket) error {
	if c.selectedAddr == "" {
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

	addr, err := net.ResolveUDPAddr("udp", c.selectedAddr)
	if err != nil {
		return err
	}

	if len(pkt) > packet.MaxContentSize {
		panic(fmt.Errorf("bad packet length %d", len(pkt)))
	}

	logrus.Debugf("writing udp packet to %s - %s", c.name, c.ip)
	_, err = c.connUdp.WriteToUDP(pkt.ToPacket(), addr)

	c.lastUsed = time.Now()
	c.aes.Revive(c.name)

	return err
}

func (c *Conn) WriteTCP(pkt packet.TcpPacket) error {
	if c.connTcp == nil {
		if c.selectedAddr == "" {
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

	c.lastUsed = time.Now()
	c.aes.Revive(c.name)

	return err
}
