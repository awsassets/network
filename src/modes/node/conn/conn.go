package conn

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
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

	connUdp *net.UDPConn
	connTcp *net.TCPConn
	// connTcpMtx sync.Mutex

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

	conn.connUdp = udp
	conn.ctx = ctx
	conn.cancel = cancel

	c.aes.GetOrNew(node.Name)

	go func() {
		conn.Ping()
		c.Stop(conn.ip)
	}()

	go func() {
		conn.ManageTCP()
		c.Stop(conn.ip)
	}()

	return conn
}

func (c *Conn) ManageTCP() {
	first := true
	for {
		if c.connTcp != nil {
			_ = c.connTcp.Close()
			c.connTcp = nil
		}
		// c.connTcpMtx.Lock()
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

		for _, ip := range node.AdvertiseAddresses {
			addr, err := net.ResolveTCPAddr("tcp", ip)
			if err != nil {
				continue
			}
			c.connTcp, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				c.connTcp = nil
				continue
			}
			c.connTcp.SetNoDelay(true)
			c.connTcp.SetKeepAlive(false)
			c.connTcp.SetLinger(0)
			break
		}

		if c.connTcp == nil {
			logrus.Warnf("cannot find tcp route to node: %s", c.ip)
			// c.connTcpMtx.Unlock()
			continue
		}

		id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
		data := make([]byte, 1+4+16+2)
		binary.BigEndian.PutUint16(data, uint16(len(packet.WrapIpPkt(data[2:], packet.PacketTypePing, utils.OrPanic(id.MarshalBinary())[0].([]byte), net.ParseIP(*c.ourIP).To4()))))
		if _, err := c.connTcp.Write(data); err != nil {
			logrus.Error("failed to write: ", err)
		}
		pid := hex.EncodeToString(utils.OrPanic(id.MarshalBinary())[0].([]byte))

		pingCh := make(chan string, 1)
		go func() {
			buff := make([]byte, packet.MTU+23)
			defer close(pingCh)
			bconn := bufio.NewReader(c.connTcp)
			for {
				_, err := io.ReadFull(bconn, buff[:2])
				if err == io.EOF {
					_, err = io.ReadFull(bconn, buff[:2])
				}
				if err != nil {
					logrus.Error(err)
					return
				}
				i := int(binary.BigEndian.Uint16(buff[:2])) + 2
				_, err = io.ReadFull(bconn, buff[2:i])
				if err == io.EOF {
					_, err = io.ReadFull(bconn, buff[:2])
				}
				if err != nil {
					logrus.Error(err)
					return
				}
				if i < 17 {
					logrus.Warn("bad packet read: ", utils.B2S(buff))
					continue
				}
				b := buff[2:i]
				switch packet.PacketType(b[0]) {
				case packet.PacketTypePong:
					pingCh <- fmt.Sprintf("0%s", hex.EncodeToString(b[1:17]))
				case packet.PacketTypePongAesPresent:
					pingCh <- fmt.Sprintf("1%s.%s", hex.EncodeToString(b[1:17]), hex.EncodeToString(b[17:]))
				}
			}
		}()

		timeout := time.After(time.Second * 5)
		aesKeyExchanged := false
		timedout := false
	outer:
		for {
			select {
			case ping, ok := <-pingCh:
				if !ok {
					timedout = true
					break outer
				}
				idx := strings.IndexRune(ping, '.')
				if idx == -1 {
					idx = len(ping)
				}
				if pid != ping[1:idx] {
					continue
				}
				aesKeyExchanged = ping[0] == '1'
				if aesKeyExchanged {
					// verify it
					data, _ := hex.DecodeString(ping[idx+1:])
					dec, err := c.Aes().Decrypt(data)
					if err != nil {
						logrus.Error(err)
						aesKeyExchanged = false
						break
					}

					t := time.Unix(0, int64(binary.LittleEndian.Uint64(dec)))
					if !t.After(time.Now().Add(-time.Second * 10)) {
						aesKeyExchanged = false
					}
				}
				break outer
			case <-timeout:
				timedout = true
				break outer
			}
		}
		if timedout {
			// c.connTcpMtx.Unlock()
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

			data := make([]byte, len(encrypted)+1+4+16+2)
			id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
			packet.WrapIpPkt(data[2:], packet.PacketTypeExchange, utils.OrPanic(id.MarshalBinary())[0].([]byte), net.ParseIP(*c.ourIP).To4())
			copy(data[23:], encrypted)
			binary.BigEndian.PutUint16(data, uint16(len(data)-2))
			if _, err := c.connTcp.Write(data); err != nil {
				logrus.Error("failed to write: ", err)
			}
			logrus.Debug("sent encrypted data")
		}
		// c.connTcpMtx.Unlock()
		for range pingCh {
		}
	}
}

func (c *Conn) Ping() {
	tick := time.NewTicker(time.Millisecond * 100)
	defer tick.Stop()
	defer c.connUdp.Close()
	pingCh := make(chan string, 1000)
	defer close(pingCh)
	go func() {
		buff := make([]byte, packet.MTU+21)
		for {
			n, _, err := c.connUdp.ReadFromUDP(buff)
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
			default:
				logrus.Warn("bad response: ", b)
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
			for i := 0; i < 5; i++ {
				if _, err = c.connUdp.WriteToUDP(data, addr); err != nil {
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
						logrus.Errorf("%s - %v - %v", err, data, ping)
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
				_ = c.WriteUDP(data)
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

func (c *Conn) WriteUDP(data []byte) error {
	addr, err := net.ResolveUDPAddr("udp", c.selectedAddr)
	if err != nil {
		return err
	}

	if len(data) > packet.MTU+21 {
		panic(fmt.Sprintf("bad packet length %d", len(data)))
	}

	_, err = c.connUdp.WriteToUDP(data, addr)
	return err
}

func (c *Conn) WriteTCP(data []byte) error {
	if c.connTcp == nil {
		// fallback to udp if we cannot use tcp
		logrus.Warnf("using udp since tcp seems to be down on node %s - %s", c.name, c.ip)
		return c.WriteUDP(data[2:])
	}

	// c.connTcpMtx.Lock()
	_, err := c.connTcp.Write(data)
	if len(data) > packet.MTU+23 {
		panic(fmt.Sprintf("bad packet length %d", len(data)))
	}
	// c.connTcpMtx.Unlock()
	return err
}
