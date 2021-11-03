package base

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/signal"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/network"
	"github.com/disembark/network/src/packet"
	aes_store "github.com/disembark/network/src/store/aes"
	conn_store "github.com/disembark/network/src/store/conn"
	dns_store "github.com/disembark/network/src/store/dns"
	node_store "github.com/disembark/network/src/store/node"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water/waterutil"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/ipv4"
)

type Client struct {
	NodeStore *node_store.Store
	ConnStore *conn_store.Store
	AesStore  *aes_store.Store
	DnsStore  *dns_store.Store

	SignalClient *signal.Client

	State types.JoinPayloadNode
	IP    *string

	Config  *configure.Config
	Private *ecies.PrivateKey

	Network network.NetworkInterface

	StartTime int64
}

func NewClient(config *configure.Config) *Client {
	netInt := network.CreateTun()
	dns := dns_store.New()

	nodes := node_store.NewWithDns(dns)

	b, _ := pem.Decode(utils.S2B(config.ClientPrivateKey))
	cert, _ := x509.ParsePKCS8PrivateKey(b.Bytes)

	ip := utils.StringPointer("")

	c := &Client{
		NodeStore: nodes,
		ConnStore: conn_store.New(nodes, ip),
		AesStore:  aes_store.New(),
		DnsStore:  dns,

		Network: netInt,

		Private: ecies.ImportECDSA(cert.(*ecdsa.PrivateKey)),

		IP:        ip,
		Config:    config,
		StartTime: time.Now().UnixNano(),
	}

	c.configureDNS()

	go func() {
		tick := time.NewTicker(time.Second * 10)
		for range tick.C {
			c.configureDNS()
		}
	}()

	for _, v := range c.Network.GetRaws() {
		go c.ProcessDevice(v)
	}

	return c
}

func (c *Client) configureDNS() {
	proxy, err := c.Network.ConfigureDNS()
	if err != nil {
		logrus.Fatal("failed to setup dns: ", err)
	}

	logrus.Debug("configured dns resolve: ", proxy)

	c.DnsStore.SetProxy(proxy)
}

func (c *Client) ProcessSignal() {
	go func() {
		tick := time.NewTicker(time.Minute * 5)
		for range tick.C {
			_ = c.SignalClient.Write(types.Message{Type: types.MessageTypePing})
		}
	}()
	for msg := range c.SignalClient.Messages() {
		switch msg.Type {
		case types.MessageTypeNodeState:
			pl := types.MessageNodeState{}
			if err := json.Unmarshal(msg.Payload, &pl); err != nil {
				logrus.Warn("bad message: ", err)
				continue
			}

			c.State = pl.Current
			*c.IP = pl.Current.IP
			c.NodeStore.Merge(pl.Nodes)
			c.Config.SignalServers = pl.Signals
			_ = c.Config.Save()

			c.Network.SetIP(pl.Current.IP)
			logrus.Debug("ourIP: ", pl.Current.IP)
		case types.MessageTypeNodeRegister:
			pl := types.MessageNodeRegister{}
			if err := json.Unmarshal(msg.Payload, &pl); err != nil {
				logrus.Warn("bad message: ", err)
				continue
			}

			c.NodeStore.SetNode(pl.Node.Name, node_store.Node{JoinPayloadNode: pl.Node})
			logrus.Infof("new node %s at %s", pl.Node.Name, pl.Node.IP)
		case types.MessageTypeSignalRegister:
			pl := types.MessageSignalRegister{}
			if err := json.Unmarshal(msg.Payload, &pl); err != nil {
				logrus.Warn("bad message: ", err)
				continue
			}

			c.NodeStore.Merge(pl.Signal.Nodes)

			found := false
			for i, v := range c.Config.SignalServers {
				if v.Name == pl.Signal.Name {
					found = true
					c.Config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
				}
			}
			if !found {
				c.Config.SignalServers = append(c.Config.SignalServers, pl.Signal.SignalServer)
			}
			for _, sig := range pl.Signal.Signals {
				found := false
				for i, v := range c.Config.SignalServers {
					if v.Name == sig.Name {
						found = true
						c.Config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
					}
				}
				if !found {
					c.Config.SignalServers = append(c.Config.SignalServers, sig)
				}
			}
		case types.MessageTypeSignalDeregister:
			// unsupported
		}
	}
}

func (c *Client) ProcessDevice(dev network.Device) {
	relayPc := packet.NewConstructor()
	stdPc := packet.NewConstructorWithBuffer(relayPc.Buffer()[packet.RelayPacketHeaderLength-packet.TCPHeaderLength:])
	// since we are doing aes encryption on this data, we need to make the packet data slightly bigger to allow for the aes padding to be at the beginning.
	// to avoid copying data from one buffer to another we must use the pc buffer here otherwise we end up with copying data.
	ifaceBuff := stdPc.Buffer() // this is a raw packet buffer and will result in a bad packet if we read from it, so we must not do that.
	// we want to make sure the network packet data lands where it is going to be in the final data packet.
	// to do this we must look at where the data should be.
	// There is a header for the datapacket which needs to be offset here.
	// we need to check if this changes ever so that we can update the underlying buffer with the new ip to avoid copying data
	currentIp := *c.IP

	for i, v := range net.ParseIP(*c.IP).To4() {
		ifaceBuff[1+i] = v
	}

	for {
		n, err := dev.Read(ifaceBuff[packet.DataPacketHeaderLength+aes.BlockSize:])
		if err != nil || n < ipv4.HeaderLen || n > packet.MTU {
			continue
		}

		b := ifaceBuff[packet.DataPacketHeaderLength : packet.DataPacketHeaderLength+n+aes.BlockSize]

		pkt := b[aes.BlockSize:]

		if !waterutil.IsIPv4(pkt) {
			continue
		}

		srcAddr, dstAddr, isTcp := netutil.GetAddr(pkt)
		if srcAddr == "" || dstAddr == "" {
			continue
		}

		node, ok := c.NodeStore.GetNode(netutil.RemovePort(dstAddr))
		if !ok {
			continue
		}

		conn := c.ConnStore.New(node.IP)
		if conn == nil {
			logrus.Warn("conn manager has a bad node tree")
			continue
		}

		_, err = conn.Aes().Encrypt(b)
		if err != nil {
			logrus.Warn("failed to encrypt pkt: ", err)
			continue
		}

		var tcpPkt packet.TcpPacket
		if node.Relay {
			relayPc.MakeRelayDataPacketSize(n+aes.BlockSize, net.ParseIP(node.IP))
			tcpPkt = relayPc.ToTCP()
		} else {
			stdPc.MakeDataPacketSize(n + aes.BlockSize)
			tcpPkt = stdPc.ToTCP()
		}

		if *c.IP != currentIp {
			currentIp = *c.IP

			for i, v := range net.ParseIP(*c.IP).To4() {
				ifaceBuff[1+i] = v
			}
		}

		if isTcp {
			_ = conn.WriteTCP(tcpPkt)
		} else {
			_ = conn.WriteUDP(tcpPkt)
		}
	}
}

func (c *Client) HandlePacket(pc *packet.PacketConstructor, conn net.Conn, addr *net.UDPAddr, isUDP bool, isRelayed bool) {
	pkt := pc.ToPacket()

	if !pkt.Valid() {
		logrus.Debug("invalid packet read")
		return
	}

	switch pkt.Type() {
	case packet.PacketTypeData:
		pkt := packet.DataPacket(pkt)

		node, ok := c.NodeStore.GetNode(pkt.IP().String())
		if !ok {
			logrus.Debug("unknown node ip: ", pkt.IP())
			return
		}

		aesKey := c.AesStore.Get(node.Name)
		if aesKey == nil {
			logrus.Warnf("dropping packet due to no key exchange: %s - %s", node.Name, node.IP)
			return
		}

		c.AesStore.Revive(node.Name)

		b, err := aesKey.Decrypt(pkt.Data())
		if err != nil {
			logrus.Warnf("bad encryption on block: %s - %s : %e", node.Name, node.IP, err)
			return
		}

		if !waterutil.IsIPv4(b) {
			logrus.Warn("dropping packet because not IPv4")
			return
		}

		srcAddr, dstAddr, _ := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			return
		}

		destIp := netutil.RemovePort(dstAddr)
		if destIp != c.State.IP {
			logrus.Warn("bad packet from ext unknown ip dest: ", destIp)
			return
		}

		srcIp := netutil.RemovePort(srcAddr)
		if srcIp != node.IP {
			logrus.Warn("bad packet from ext unknown ip src: ", srcIp)
			return
		}

		_, _ = c.Network.GetNext().Write(b)

		logrus.Debugf("data from %s - %s", node.Name, node.IP)
	case packet.PacketTypeExchange:
		pkt := packet.ExchangePacket(pkt)

		node, ok := c.NodeStore.GetNode(pkt.IP().String())
		if !ok {
			logrus.Debug("unknown node ip: ", pkt.IP())
			return
		}

		aesKey, err := c.Private.Decrypt(pkt.Data(), nil, nil)
		if err != nil {
			logrus.Errorf("bad encryption on aes key: %s", err.Error())
			return
		}

		if len(aesKey) != 32 {
			logrus.Error("bad aes key length: ", len(aesKey))
			return
		}

		c.AesStore.Store(node.Name, aesKey)

		logrus.Debugf("exchange from %s - %s", node.Name, node.IP)
	case packet.PacketTypePing:
		pkt := packet.PingPacket(pkt)

		node, ok := c.NodeStore.GetNode(pkt.IP().String())
		if !ok {
			logrus.Debug("unknown node ip: ", pkt.IP())
			return
		}

		// check if we have an aes key to this ip
		aesKey := c.AesStore.Get(node.Name)
		id := pkt.ID()
		if aesKey == nil {
			if isRelayed {
				pc.MakeRelayPongPacket(id, net.ParseIP(node.IP))
			} else {
				pc.MakePongPacket(id)
			}

			if isUDP {
				if addr == nil {
					if _, err := conn.Write(pc.ToUDP()); err != nil {
						logrus.Warnf("failed to respond to ping: %v", err)
						return
					}
				} else {
					if _, err := conn.(*net.UDPConn).WriteToUDP(pc.ToUDP(), addr); err != nil {
						logrus.Warnf("failed to respond to ping: %v", err)
						return
					}
				}
			} else {
				if _, err := conn.Write(pc.ToTCP()); err != nil {
					logrus.Warnf("failed to respond to ping: %v", err)
					return
				}
			}

			logrus.Debugf("ping from %s - %s - %s", node.Name, node.IP, id)
		} else {
			hmacBuffer := make([]byte, 32)

			_, _ = rand.Reader.Read(hmacBuffer)

			h := hmac.New(sha3.New512, aesKey.KeyRaw())
			_, _ = h.Write(hmacBuffer)
			hMAC := h.Sum(nil)

			if isRelayed {
				pc.MakeRelayPongAesPacket(id, hmacBuffer, hMAC, net.ParseIP(node.IP))
			} else {
				pc.MakePongAesPacket(id, hmacBuffer, hMAC)
			}

			if isUDP {
				if addr == nil {
					if _, err := conn.Write(pc.ToUDP()); err != nil {
						logrus.Warnf("failed to respond to ping: %v", err)
						return
					}
				} else {
					if _, err := conn.(*net.UDPConn).WriteToUDP(pc.ToUDP(), addr); err != nil {
						logrus.Warnf("failed to respond to ping: %v", err)
						return
					}
				}
			} else {
				if _, err := conn.Write(pc.ToTCP()); err != nil {
					logrus.Warnf("failed to respond to ping: %v", err)
					return
				}
			}

			logrus.Debugf("ping aes from %s - %s - %s", node.Name, node.IP, id)
		}
	default:
		logrus.Warnf("unsupported packet type: %d", pkt.Type())
	}
}
