package node

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/node/aes"
	"github.com/disembark/network/src/modes/node/conn"
	"github.com/disembark/network/src/modes/node/dns"
	"github.com/disembark/network/src/modes/node/network"
	"github.com/disembark/network/src/modes/node/packet"
	"github.com/disembark/network/src/modes/signal/client"
	"github.com/disembark/network/src/modes/signal/node"
	"github.com/disembark/network/src/modes/signal/types"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/utils"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water/waterutil"
	"golang.org/x/crypto/sha3"
)

type Node struct {
	nodes   *node.NodeStore
	conn    *conn.ConnStore
	client  *client.Client
	state   types.JoinPayloadNode
	ip      *string
	config  *configure.Config
	aes     *aes.AesStore
	private *ecies.PrivateKey
	network *network.NetworkInterface
	dns     *dns.DNS

	startTime int64
}

func New(config *configure.Config) {
	logrus.Info("starting node")
	ctx, cancel := context.WithCancel(context.Background())

	ch := make(chan os.Signal, 1)

	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	localAddr, err := net.ResolveUDPAddr("udp", config.Bind)
	if err != nil {
		logrus.Fatal("failed to get udp socket:", err)
	}

	netInt := network.CreateTun()

	d := dns.New()
	nodes := node.NewWithDns(d)

	ip := ""

	ipp := &ip

	b, _ := pem.Decode(utils.S2B(config.ClientPrivateKey))
	cert, _ := x509.ParsePKCS8PrivateKey(b.Bytes)

	node := &Node{
		nodes:     nodes,
		client:    client.New(ctx, config),
		config:    config,
		conn:      conn.New(nodes, ipp),
		startTime: time.Now().UnixNano(),
		ip:        ipp,
		aes:       aes.New(),
		private:   ecies.ImportECDSA(cert.(*ecdsa.PrivateKey)),
		network:   netInt,
		dns:       d,
	}

	done := make(chan struct{})
	go func() {
		<-ch
		go func() {
			select {
			case <-ch:
			case <-time.After(time.Minute):
			}
			logrus.Fatal("force shutdown")
		}()
		cancel()

		<-node.client.Done()

		close(done)
	}()

	go node.ProcessIface()
	go node.ProcessSignal()

	{
		c, err := net.ListenUDP("udp", localAddr)
		if err != nil {
			log.Fatalln("failed to listen on udp socket:", err)
		}
		defer c.Close()
		go node.ListenConn(c)
	}

	{
		c, err := net.Listen("tcp", localAddr.String())
		if err != nil {
			log.Fatalln("failed to listen on udp socket:", err)
		}
		defer c.Close()
		go node.ListenTCP(c.(*net.TCPListener))
	}

	<-done

	logrus.Info("shutdown")
	os.Exit(0)
}

func (n *Node) ProcessSignal() {
	go func() {
		tick := time.NewTicker(time.Minute * 5)
		for range tick.C {
			_ = n.client.Write(types.Message{Type: types.MessageTypePing})
		}
	}()
	for msg := range n.client.Messages() {
		switch msg.Type {
		case types.MessageTypeNodeState:
			pl := types.MessageNodeState{}
			if err := json.Unmarshal(msg.Payload, &pl); err != nil {
				logrus.Warn("bad message: ", err)
				continue
			}

			n.state = pl.Current
			*n.ip = pl.Current.IP
			n.nodes.Merge(pl.Nodes)
			n.config.SignalServers = pl.Signals
			_ = n.config.Save()

			n.network.SetIP(pl.Current.IP)
		case types.MessageTypeNodeRegister:
			pl := types.MessageNodeRegister{}
			if err := json.Unmarshal(msg.Payload, &pl); err != nil {
				logrus.Warn("bad message: ", err)
				continue
			}

			n.nodes.SetNode(pl.Node.Name, node.Node{JoinPayloadNode: pl.Node})
			logrus.Infof("new node %s at %s", pl.Node.Name, pl.Node.IP)
		case types.MessageTypeSignalRegister:
			pl := types.MessageSignalRegister{}
			if err := json.Unmarshal(msg.Payload, &pl); err != nil {
				logrus.Warn("bad message: ", err)
				continue
			}

			n.nodes.Merge(pl.Signal.Nodes)

			found := false
			for i, v := range n.config.SignalServers {
				if v.Name == pl.Signal.Name {
					found = true
					n.config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
				}
			}
			if !found {
				n.config.SignalServers = append(n.config.SignalServers, pl.Signal.SignalServer)
			}
			for _, sig := range pl.Signal.Signals {
				found := false
				for i, v := range n.config.SignalServers {
					if v.Name == sig.Name {
						found = true
						n.config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
					}
				}
				if !found {
					n.config.SignalServers = append(n.config.SignalServers, sig)
				}
			}
		case types.MessageTypeSignalDeregister:
			// unsupported
		}
	}
}

func (r *Node) ListenConn(conn net.Conn) {
	defer conn.Close()

	connType := "tcp"
	type writeFn func() error
	type readFn func() (packet.Packet, error)

	var read readFn
	var write writeFn

	isTCP := false

	pc := packet.NewConstructor()

	switch c := conn.(type) {
	case *net.UDPConn:
		connType = "udp"
		var (
			err  error
			addr *net.UDPAddr
		)
		read = func() (packet.Packet, error) {
			addr, err = pc.ReadUDP(c)
			return pc.ToPacket(), err
		}
		write = func() error {
			_, err := c.WriteToUDP(pc.ToUDP(), addr)
			return err
		}
	case *net.TCPConn:
		isTCP = true
		bconn := bufio.NewReaderSize(c, packet.MTU*5)

		read = func() (packet.Packet, error) {
			err := pc.ReadTCP(bconn)
			return pc.ToPacket(), err
		}

		write = func() error {
			_, err := c.Write(pc.ToTCP())
			return err
		}
	}
	for {
		pkt, err := read()
		if err != nil {
			if isTCP {
				return
			}
			logrus.Warn("read err: ", err)
			continue
		}

		if !pkt.Valid() {
			logrus.Debug(connType, " invalid packet read")
			continue
		}

		switch pkt.Type() {
		case packet.PacketTypeData:
			pkt := packet.DataPacket(pkt)

			node, ok := r.nodes.GetNode(pkt.IP().String())
			if !ok {
				logrus.Debug(connType, " unknown node ip: ", pkt.IP())
				continue
			}

			aesKey := r.aes.Get(node.Name)
			if aesKey == nil {
				logrus.Warnf("dropping packet due to no key exchange: %s - %s", node.Name, node.IP)
				continue
			}

			// todo perhaps we can buffer this?
			b, err := aesKey.Decrypt(pkt.Data())
			if err != nil {
				logrus.Warnf("bad encryption on block: %s - %s : %e", node.Name, node.IP, err)
				continue
			}

			if !waterutil.IsIPv4(b) {
				logrus.Warn("dropping packet because not IPv4")
				continue
			}

			srcAddr, dstAddr, _ := netutil.GetAddr(b)
			if srcAddr == "" || dstAddr == "" {
				continue
			}

			destIp := netutil.RemovePort(dstAddr)
			if destIp != r.state.IP {
				logrus.Warn("bad packet from ext unknown ip dest: ", destIp)
				continue
			}

			srcIp := netutil.RemovePort(srcAddr)
			if srcIp != node.IP {
				logrus.Warn("bad packet from ext unknown ip src: ", srcIp)
				continue
			}

			_, _ = r.network.GetRaw().Write(b)

			logrus.Debugf("%s data from %s - %s", connType, node.Name, node.IP)
		case packet.PacketTypeExchange:
			pkt := packet.ExchangePacket(pkt)

			node, ok := r.nodes.GetNode(pkt.IP().String())
			if !ok {
				logrus.Debug(connType, " unknown node ip: ", pkt.IP())
				continue
			}

			aesKey, err := r.private.Decrypt(pkt.Data(), nil, nil)
			if err != nil {
				logrus.Errorf("%s bad encryption on aes key: %s", connType, err.Error())
				continue
			}

			if len(aesKey) != 32 {
				logrus.Error(connType, "bad aes key length: ", len(aesKey))
				continue
			}

			r.aes.Store(node.Name, aesKey)

			logrus.Debugf("%s exchange from %s - %s", connType, node.Name, node.IP)
		case packet.PacketTypePing:
			pkt := packet.PingPacket(pkt)

			node, ok := r.nodes.GetNode(pkt.IP().String())
			if !ok {
				logrus.Debug(connType, " unknown node ip: ", pkt.IP())
				continue
			}

			// check if we have an aes key to this ip
			aesKey := r.aes.Get(node.Name)
			id := pkt.ID()
			if aesKey == nil {
				pc.MakePongPacket(id)

				if err := write(); err != nil {
					logrus.Warn("failed to write packet: ", err)
				}

				logrus.Debugf("%s ping from %s - %s - %s", connType, node.Name, node.IP, id)
			} else {
				data := make([]byte, 32)
				_, _ = rand.Reader.Read(data)

				h := hmac.New(sha3.New512, aesKey.KeyRaw())
				_, _ = h.Write(data)
				hMAC := h.Sum(nil)

				pc.MakePongAesPacket(pkt.ID(), data, hMAC)

				if err := write(); err != nil {
					logrus.Warn("failed to write packet: ", err)
				}

				logrus.Debugf("%s ping aes from %s - %s - %s", connType, node.Name, node.IP, id)
			}
		default:
			logrus.Warnf("%s unsupported packet type: %d", connType, pkt.Type())
			continue
		}
	}
}

func (r *Node) ListenTCP(ln *net.TCPListener) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			continue
		}
		go r.ListenConn(conn)
	}
}

func (r *Node) ProcessIface() {
	pc := packet.NewConstructor()
	ifaceBuff := make([]byte, packet.MTU)

	for {
		n, err := r.network.GetRaw().Read(ifaceBuff)
		if err != nil || n == 0 {
			continue
		}
		b := ifaceBuff[:n]
		if !waterutil.IsIPv4(b) {
			continue
		}

		srcAddr, dstAddr, isTcp := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}

		node, ok := r.nodes.GetNode(netutil.RemovePort(dstAddr))
		if !ok {
			continue
		}

		conn := r.conn.New(node.IP)

		data, err := conn.Aes().Encrypt(b)
		if err != nil {
			logrus.Warn("failed to encrypt pkt: ", err)
			continue
		}

		pc.MakeDataPacket(data, net.ParseIP(*r.ip))

		if isTcp {
			_ = conn.WriteTCP(pc.ToTCP())
		} else {
			_ = conn.WriteUDP(pc.ToUDP())
		}
	}
}
