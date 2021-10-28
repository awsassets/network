package node

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/node/aes"
	"github.com/disembark/network/src/modes/node/conn"
	"github.com/disembark/network/src/modes/node/packet"
	"github.com/disembark/network/src/modes/signal/client"
	"github.com/disembark/network/src/modes/signal/node"
	"github.com/disembark/network/src/modes/signal/types"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/utils"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	reuse "github.com/libp2p/go-reuseport"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
)

type Node struct {
	nodes   *node.NodeStore
	conn    *conn.ConnStore
	client  *client.Client
	state   types.JoinPayloadNode
	ip      *string
	config  *configure.Config
	iface   *water.Interface
	aes     *aes.AesStore
	private *ecies.PrivateKey

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

	nodes := node.New()

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

	for i := 0; i < runtime.NumCPU(); i++ {
		c, err := reuse.ListenPacket("udp", localAddr.String())
		if err != nil {
			log.Fatalln("failed to listen on udp socket:", err)
		}
		defer c.Close()
		go node.ListenConn(c.(*net.UDPConn))
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		c, err := reuse.Listen("tcp", localAddr.String())
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

			if n.iface != nil {
				_ = n.iface.Close()
				n.iface = nil
			}
			n.iface = CreateTun(n.state.IP)
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
	buf := make([]byte, packet.MTU+23) // first byte is a packet type.
	defer conn.Close()
	var connType string
	type writeFn func([]byte) (int, error)
	type readFn func() (writeFn, []byte, int, error)

	var read readFn
	isTCP := false

	switch c := conn.(type) {
	case *net.UDPConn:
		connType = "udp"
		read = func() (writeFn, []byte, int, error) {
			n, addr, err := c.ReadFromUDP(buf[:len(buf)-2])
			if err == io.EOF {
				err = nil
			}
			return func(b []byte) (int, error) {
				return c.WriteToUDP(b, addr)
			}, buf[:n], n, err
		}
	case *net.TCPConn:
		isTCP = true
		bconn := bufio.NewReader(c)
		read = func() (writeFn, []byte, int, error) {
			n, err := io.ReadFull(bconn, buf[:2])
			if err == io.EOF {
				n, err = io.ReadFull(bconn, buf[:2])
			}
			if err != nil {
				return nil, nil, n, err
			}

			b := buf[2 : binary.BigEndian.Uint16(buf[:2])+2]
			n, err = io.ReadFull(bconn, b)
			if err == io.EOF {
				n, err = io.ReadFull(bconn, b)
			}

			return func(b []byte) (int, error) {
				copy(buf[2:], b)
				binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
				return c.Write(buf[:len(b)+2])
			}, b[:n], n, err
		}
	}
	for {
		write, data, n, err := read()
		if err != nil {
			logrus.Warn("read err: ", err)
			if isTCP {
				return
			}
		}
		switch packet.PacketType(data[0]) {
		case packet.PacketTypeData:
			if n < 5 {
				logrus.Warn("bad packet length")
				continue
			}
			// we must decrypt this packet.
			ip := net.IPv4(data[1], data[2], data[3], data[4]).To4().String()
			node, ok := r.nodes.GetNode(ip)
			if !ok {
				logrus.Error("unknown node conn: ", ip)
				continue
			}

			b := data[5:n]

			aesKey := r.aes.Get(node.Name)
			if aesKey == nil {
				logrus.Warnf("dropping packet due to no key exchange: %s - %s", node.Name, node.IP)
				continue
			}

			b, err = aesKey.Decrypt(b)
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
			if _, ok := r.nodes.GetNode(srcIp); !ok {
				logrus.Warn("bad packet from ext unknown ip src: ", srcIp)
				continue
			}

			_, _ = r.iface.Write(b)
			logrus.Debugf("wrote packet (%d bytes) from %s - %s", len(b), node.IP, node.Name)
		case packet.PacketTypeExchange:
			// this is a aes key exchange.
			if n < 21 {
				continue
			}
			ip := net.IPv4(data[1], data[2], data[3], data[4]).To4().String()

			node, ok := r.nodes.GetNode(ip)
			if !ok {
				logrus.Warn(connType, "unknown node ip: ", ip)
				continue
			}

			aesKeyEncrypted := data[21:n]
			aesKey, err := r.private.Decrypt(aesKeyEncrypted, nil, nil)
			if err != nil {
				logrus.Warnf("%s bad encryption on aes key: %d : %e", connType, len(aesKeyEncrypted), err)
				continue
			}

			if len(aesKey) != 32 {
				logrus.Warn(connType, "bad aes key length: ", len(aesKey))
				continue
			}

			r.aes.Store(node.Name, aesKey)

			_, _ = write(packet.WrapPkt(buf, packet.PacketTypeExchangeResponse, data[5:21]))

			logrus.Debugf("%s stored aes key from %s - %s", connType, node.IP, node.Name)
		case packet.PacketTypePing:
			if n < 21 {
				continue
			}
			ip := net.IPv4(data[1], data[2], data[3], data[4]).To4().String()

			node, ok := r.nodes.GetNode(ip)
			if !ok {
				logrus.Warn(connType, " unknown node ip: ", ip)
				continue
			}

			// check if we have an aes key to this ip
			aesKey := r.aes.Get(node.Name)
			if aesKey == nil {
				write(packet.WrapPkt(buf, packet.PacketTypePong, data[5:21]))

				logrus.Debugf("%s pong from %s - %s", connType, node.IP, node.Name)
			} else {
				b := make([]byte, 8)
				binary.LittleEndian.PutUint64(b, uint64(time.Now().UnixNano()))
				packet.WrapPkt(buf, packet.PacketTypePongAesPresent, data[5:21])
				data := utils.OrPanic(aesKey.Encrypt(b))[0].([]byte)
				copy(buf[17:], data)
				write(buf[:17+len(data)])
				logrus.Debugf("%s pong aes from %s - %s", connType, node.IP, node.Name)
			}
		default:
			logrus.Warnf("%s unknown packet type: %d - %d - %d \n%s", connType, data[0], n, packet.MTU+21, spew.Sdump(data[:n]))
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
		conn.SetNoDelay(true)
		conn.SetKeepAlive(false)
		conn.SetLinger(0)
		go r.ListenConn(conn)
	}
}

func (r *Node) ProcessIface() {
	buf := make([]byte, packet.MTU+23)
	for {
		if r.iface == nil {
			time.Sleep(time.Millisecond * 50)
			continue
		}
		n, err := r.iface.Read(buf[:packet.MTU])
		if err != nil || n == 0 {
			continue
		}
		b := buf[:n]
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

		data = packet.WrapData(buf[2:], net.ParseIP(*r.ip), data)
		if isTcp {
			binary.BigEndian.PutUint16(buf, uint16(len(data)))
			_ = conn.WriteTCP(buf[:len(data)+2])
		} else {
			_ = conn.WriteUDP(data)
		}

	}
}
