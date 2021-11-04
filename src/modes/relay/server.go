package relay

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	sig "os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/disembark/network/src/cache"
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/loadbalancer"
	"github.com/disembark/network/src/modes/signal"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/packet"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"

	conn_store "github.com/disembark/network/src/modes/relay/conn"
	node_store "github.com/disembark/network/src/store/node"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type Server struct {
	nodes *node_store.Store

	client *signal.Client

	config     *configure.Config
	tokenStore *cache.Cache
	pingStore  *cache.Cache

	conns *conn_store.Store

	udpConnLb *loadbalancer.LoadBalancer

	startTime int64
}

type pingEvent struct {
	conn  net.Conn
	addr  *net.UDPAddr
	isUDP bool
}

func NewServer(config *configure.Config) {
	logrus.Info("starting relay")
	ctx, cancel := context.WithCancel(context.Background())

	ch := make(chan os.Signal, 1)

	sig.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	nodes := node_store.New()

	udpConns, err := netutil.ListenUDP(config.Bind)
	if err != nil {
		logrus.Fatal("failed to listen on udp socket: ", err)
	}

	lb := loadbalancer.NewLoadBalancer()

	server := &Server{
		nodes:      nodes,
		client:     signal.NewClient(ctx, config, nil),
		config:     config,
		startTime:  time.Now().UnixNano(),
		tokenStore: cache.New(time.Minute*5, time.Minute),
		pingStore:  cache.New(time.Minute*5, time.Minute),
		conns:      conn_store.New(nodes, lb),
		udpConnLb:  lb,
	}

	s := &fasthttp.Server{
		Handler: server.HttpHandler,
		Logger:  logrus.New(),
		Name:    "disembark",
	}

	go func() {
		if err := s.ListenAndServeTLSEmbed(config.RelayHttpBind, utils.S2B(config.SignalServerPublicKey), utils.S2B(config.SignalServerPrivateKey)); err != nil {
			logrus.Fatal("error in ListenAndServe: ", err)
		}
	}()

	go server.ProcessSignal()

	for _, v := range udpConns {
		lb.AddItem(v)
		defer v.Close()
		go server.ProcessConn(v)
	}

	tcpConns, err := netutil.ListenTCP(config.Bind)
	if err != nil {
		logrus.Fatal("failed to listen on udp socket: ", err)
	}
	for _, v := range tcpConns {
		defer v.Close()
		go server.ListenTCP(v)
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

		<-server.client.Done()

		close(done)
	}()

	<-done

	logrus.Info("shutdown")
	os.Exit(0)
}

type HttpSettingsResp struct {
	AccessPoints []string `json:"access_points"`
}

func (r *Server) HttpHandler(ctx *fasthttp.RequestCtx) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Error("panic recovered in http: ", err)
		}
	}()

	tkn, err := signal.VerifyClientJoinToken(r.config, utils.B2S(ctx.Request.Header.Peek("authentication")))
	if err != nil {
		logrus.Error("bad token: ", err.Error(), utils.B2S(ctx.Request.Header.Peek("authentication")))
		ctx.SetStatusCode(403)
		return
	}

	if tkn.Mode != configure.ModeRelayClient {
		ctx.SetStatusCode(403)
		return
	}

	if tkn.Name != utils.B2S(ctx.Request.Header.Peek("name")) {
		ctx.SetStatusCode(403)
		return
	}

	switch utils.B2S(ctx.Request.Header.Peek("mode")) {
	case "token":
		count := utils.B2S(ctx.Request.Header.Peek("count"))
		if count == "" {
			count = "1"
		}

		c, err := strconv.Atoi(count)
		if err != nil {
			ctx.SetStatusCode(400)
			return
		}

		if c <= 0 || c > 10 {
			ctx.SetStatusCode(400)
			return
		}

		tkns := make([]string, c)
		for i := range tkns {
			tkns[i] = hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte))
			r.tokenStore.Store(tkns[i], tkn.Name)
		}

		data, _ := json.Marshal(tkns)

		ctx.SetStatusCode(200)

		ctx.Response.Header.Add("Content-Type", "application/json")
		ctx.Response.Header.Add("Content-Length", strconv.Itoa(len(data)))

		ctx.SetBody(data)
	case "settings":
		data, _ := json.Marshal(HttpSettingsResp{
			AccessPoints: r.config.AdvertiseAddresses,
		})

		ctx.SetStatusCode(200)

		ctx.Response.Header.Add("Content-Type", "application/json")
		ctx.Response.Header.Add("Content-Length", strconv.Itoa(len(data)))

		ctx.SetBody(data)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
	}
}

func (n *Server) ProcessSignal() {
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

			n.nodes.Merge(pl.Nodes)
			n.config.SignalServers = pl.Signals
			_ = n.config.Save()
		case types.MessageTypeNodeRegister:
			pl := types.MessageNodeRegister{}
			if err := json.Unmarshal(msg.Payload, &pl); err != nil {
				logrus.Warn("bad message: ", err)
				continue
			}

			n.nodes.SetNode(pl.Node.Name, node_store.Node{JoinPayloadNode: pl.Node})
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

func (r *Server) ProcessConn(nConn net.Conn) {
	defer nConn.Close()

	// this is a relay packet listener, therefore we need to do some tricks to save memory allocation.
	relayPc := packet.NewConstructor()
	// since the relay packet is 5 bytes longer than the normal packet, we can offset this packet by 5 bytes, but then subtract 2 bytes which is the tcp header.
	// so when we read a packet we read it in on the relayPc and then we set the size of the packet in the stdpc and read the packet from there which is copying 0 bytes in memory and allows for
	// every memory efficient code.
	stdPc := packet.NewConstructorWithBuffer(relayPc.Buffer()[packet.RelayPacketHeaderLength-packet.TCPHeaderLength:])

	var (
		addr  *net.UDPAddr
		err   error
		isTcp bool
		rConn *conn_store.Conn
	)

	defer func() {
		if rConn != nil {
			rConn.StopTCP()
		}
	}()

outer:
	for {
		switch c := nConn.(type) {
		case *net.UDPConn:
			addr, err = relayPc.ReadUDP(c)
			if err != nil {
				logrus.Warn("read err: ", err)
				continue outer
			}
		case *net.TCPConn:
			err = relayPc.ReadTCP(c)
			if err != nil {
				logrus.Debug("error reading tcp: ", err)
				return
			}
			isTcp = true
		}

		pkt := relayPc.ToPacket()

		if !pkt.Valid() {
			logrus.Debug("invalid packet read")
			continue
		}

		// the packet is a valid packet, we now need to see what the type of packet it is so we know how to handle it.
		switch pkt.Type() {
		case packet.PacketTypeRelay:
			// this is a relayed packet.
			rPkt := packet.RelayPacket(pkt)
			destIp := rPkt.DestIP()
			stdPc.SetSize(relayPc.Size() - packet.RelayPacketHeaderLength)

			if !stdPc.ToPacket().Valid() {
				panic("created an invalid packet")
			}

			pkt := stdPc.ToPacket()
			switch pkt.Type() {
			case packet.PacketTypePong, packet.PacketTypePongAes:
				// we need to handle this correctly.
				var id uuid.UUID

				if pkt.Type() == packet.PacketTypePong {
					id = packet.PongPacket(pkt).ID()
				} else {
					id = packet.PongAesPacket(pkt).ID()
				}

				if v, ok := r.pingStore.GetDelete(fmt.Sprintf("%s:%s", destIp.String(), id.String())); ok {
					logrus.Debug("pong packet: ", fmt.Sprintf("%s:%s", destIp.String(), id.String()))
					resp := v.(*pingEvent)
					if resp.isUDP {
						_, err = resp.conn.(*net.UDPConn).WriteToUDP(stdPc.ToUDP(), resp.addr)
					} else {
						_, err = resp.conn.Write(stdPc.ToTCP())
					}

					if err != nil {
						logrus.Warn("failed to respod to ping: ", err)
					}
				} else {
					logrus.Debugf("unknown pong response: %s:%s", destIp.String(), id.String())
				}

				continue outer
			}

			conn := r.conns.Get(destIp.String())
			if conn == nil {
				logrus.Debug("udp unknown conn: ", destIp.String())
				continue outer
			}

			switch pkt.Type() {
			case packet.PacketTypeData, packet.PacketTypeExchange, packet.PacketTypePing:
				// these are the packets we accept for relay proxying.
				// if the packet is a ping we must figure out how to route it, because the response is on the same connection.
				if pkt.Type() == packet.PacketTypePing {
					ping := packet.PingPacket(pkt)
					if isTcp {
						r.pingStore.Store(fmt.Sprintf("%s:%s", ping.IP().String(), ping.ID().String()), &pingEvent{
							conn: nConn,
						})
					} else {
						r.pingStore.Store(fmt.Sprintf("%s:%s", ping.IP().String(), ping.ID().String()), &pingEvent{
							conn:  nConn,
							addr:  addr,
							isUDP: true,
						})
					}
					logrus.Debug("ping packet: ", fmt.Sprintf("%s:%s", ping.IP().String(), ping.ID().String()))
				}

				if isTcp {
					_ = conn.WriteTCP(stdPc.ToTCP())
				} else {
					_ = conn.WriteUDP(stdPc.ToTCP())
				}
			default:
				logrus.Warnf("unsupported packet type: %d", pkt.Type())
				continue outer
			}
		case packet.PacketTypeRelayControlPing:
			// this is a control packet from relayed clients.
			pkt := packet.RelayControlPingPacket(pkt)

			id := pkt.ID()
			token := hex.EncodeToString(pkt.Token())

			v, ok := r.tokenStore.GetDelete(token)
			if !ok {
				logrus.Warn("bad ping packet unknown token: ", token)
				continue outer
			}

			node, ok := r.nodes.GetNode(v.(string))
			if !ok {
				logrus.Warn("bad ping packet unknown node: ", v.(string))
				continue outer
			}

			if !node.Relay {
				logrus.Warnf("bad node relay setting: %s - %s", node.Name, node.IP)
				continue outer
			}

			c := r.conns.New(node.IP)
			if c == nil {
				logrus.Warn("bad ping packet unknown node: ", v.(string))
				continue outer
			}

			relayPc.MakeRelayControlPongPacket(id)

			if isTcp {
				c.RegisterPing(nConn.(*net.TCPConn))
				rConn = c
				_, err := nConn.Write(relayPc.ToTCP())
				if err != nil {
					return
				}
				logrus.Debugf("tcp control packet from %s %s", node.Name, node.IP)
			} else {
				c.RegisterPingUDP(addr)
				_, err := nConn.(*net.UDPConn).WriteToUDP(relayPc.ToUDP(), addr)
				if err != nil {
					logrus.Warn("failed to respond to ping: ", err)
					continue
				}
				logrus.Debugf("udp control packet from %s %s", node.Name, node.IP)
			}
		default:
			logrus.Warnf("unsupported packet type: %d", pkt.Type())
			continue outer
		}
	}
}

func (r *Server) ListenTCP(ln *net.TCPListener) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			continue
		}
		go r.ProcessConn(conn)
	}
}
