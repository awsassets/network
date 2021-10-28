package conn

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/disembark/network/src/modes/node/aes"
	"github.com/disembark/network/src/modes/node/packet"
	"github.com/disembark/network/src/modes/signal/node"
	"github.com/disembark/network/src/utils"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type ConnStore struct {
	mp    *sync.Map
	nodes *node.NodeStore
	aes   *aes.AesStore
	ourIP *string
}

func New(nodes *node.NodeStore, ourIP *string) *ConnStore {
	return &ConnStore{
		mp: &sync.Map{},

		nodes: nodes,
		aes:   aes.New(),
		ourIP: ourIP,
	}
}

type Conn struct {
	name         string
	ip           string
	selectedAddr string
	ctx          context.Context
	cancel       context.CancelFunc
	conn         *net.UDPConn

	nodes *node.NodeStore
	aes   *aes.AesStore
	ourIP *string
}

func (c *ConnStore) Stop(ip string) {
	if v, ok := c.mp.LoadAndDelete(ip); ok {
		v.(*Conn).cancel()
	}
}

func (c *ConnStore) Get(ip string) *Conn {
	if v, ok := c.mp.Load(ip); ok {
		return v.(*Conn)
	}

	return nil
}

func (c *ConnStore) New(ip string) *Conn {
	node, ok := c.nodes.GetNode(ip)
	if !ok {
		return nil
	}

	conn := &Conn{
		ip:           node.IP,
		name:         node.Name,
		selectedAddr: node.AdvertiseAddresses[0],
		nodes:        c.nodes,
		aes:          c.aes,
		ourIP:        c.ourIP,
	}
	if v, ok := c.mp.LoadOrStore(node.IP, conn); ok {
		return v.(*Conn)
	}

	ctx, cancel := context.WithCancel(context.Background())
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		logrus.Fatal("failed to make a connection: ", err)
	}

	conn.conn = udp
	conn.ctx = ctx
	conn.cancel = cancel

	c.aes.GetOrNew(node.Name)

	go func() {
		conn.Ping()
		c.Stop(conn.ip)
	}()

	return conn
}

func (c *Conn) Ping() {
	tick := time.NewTicker(time.Millisecond * 100)
	defer tick.Stop()
	defer c.conn.Close()
	pingCh := make(chan string, 1000)
	defer close(pingCh)
	go func() {
		buff := make([]byte, packet.MTU)
		for {
			n, _, err := c.conn.ReadFromUDP(buff)
			if err != nil {
				logrus.Error(err)
				return
			}
			if n < 17 {
				logrus.Warn("bad packet read: ", utils.B2S(buff))
				continue
			}
			b := buff[:n]
			switch packet.PacketType(b[0]) {
			case packet.PacketTypePong:
				pingCh <- fmt.Sprintf("0%s", hex.EncodeToString(b[1:17]))
			case packet.PacketTypePongAesPresent:
				pingCh <- fmt.Sprintf("1%s.%s", hex.EncodeToString(b[1:17]), hex.EncodeToString(b[17:]))
			}
		}
	}()
	for {
		select {
		case <-tick.C:
		case <-c.ctx.Done():
			return
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
			id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
			pings[hex.EncodeToString(id[:])] = ip
			data := packet.WrapIpPkt(make([]byte, 1+4+16), packet.PacketTypePing, utils.OrPanic(id.MarshalBinary())[0].([]byte), net.ParseIP(*c.ourIP).To4())
			for i := 0; i < 50; i++ {
				if _, err = c.conn.WriteToUDP(data, addr); err != nil {
					logrus.Error("failed to write: ", err)
				}
			}
		}

		timeout := time.After(time.Second * 5)
		i := 0
		ips := make([]string, len(pings))
		aesKeyExchanged := false
	outer:
		for i < len(ips) {
			select {
			case ping := <-pingCh:
				idx := strings.IndexRune(ping, '.')
				if idx == -1 {
					idx = len(ping)
				}
				if v, ok := pings[ping[1:idx]]; ok {
					ips[i] = v
					i++
				}
				aesKeyExchanged = ping[0] == '1'
				if aesKeyExchanged {
					// verify it
					data, _ := hex.DecodeString(ping[idx+1:])
					dec, err := c.Aes().Decrypt(data)
					if err != nil {
						logrus.Error(err)
						aesKeyExchanged = false
						continue
					}

					t := time.Unix(0, int64(binary.LittleEndian.Uint64(dec)))
					if !t.After(time.Now().Add(-time.Second * 10)) {
						aesKeyExchanged = false
						continue
					}
				}
			case <-timeout:
				break outer
			}
		}

		ips = ips[:i]

		if len(ips) == 0 {
			logrus.Warnf("cannot find route to node: %s", c.ip)
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

			data := make([]byte, len(encrypted)+1+4+16)
			id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
			packet.WrapIpPkt(data, packet.PacketTypeExchange, utils.OrPanic(id.MarshalBinary())[0].([]byte), net.ParseIP(*c.ourIP).To4())
			copy(data[21:], encrypted)
			for i := 0; i < 5; i++ {
				_ = c.Write(data)
			}
			logrus.Debug("sent encrypted data")
		}
	}
}

func (c *Conn) SelectedAddress() string {
	return c.selectedAddr
}

func (c *Conn) Aes() *aes.AesKey {
	return c.aes.Get(c.name)
}

func (c *Conn) Write(data []byte) error {
	addr, err := net.ResolveUDPAddr("udp", c.selectedAddr)
	if err != nil {
		return err
	}

	_, err = c.conn.WriteToUDP(data, addr)
	return err
}
