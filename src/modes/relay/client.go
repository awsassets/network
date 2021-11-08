package relay

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	sig "os/signal"

	"github.com/davecgh/go-spew/spew"
	"github.com/disembark/network/src/base"
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/loadbalancer"
	"github.com/disembark/network/src/modes/signal"
	"github.com/disembark/network/src/netconn"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/packet"
	"github.com/disembark/network/src/utils"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type Client struct {
	*base.Client

	http *fasthttp.Client

	udpLb loadbalancer.LoadBalancer
	tcpLb loadbalancer.LoadBalancer
}

func NewClient(config *configure.Config) {
	logrus.Info("starting relay client")

	ctx, cancel := context.WithCancel(context.Background())

	ch := make(chan os.Signal, 1)

	sig.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	node := newClient(ctx, config)

	settings, err := node.GetSettings(ctx, config.RelayServerHttp)
	if err != nil {
		logrus.Fatal("failed to get settings: ", err)
	}
	node.SignalClient = signal.NewClient(ctx, config, settings.AccessPoints)
	go node.ProcessSignal()

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

		<-node.SignalClient.Done()

		close(done)
	}()

	<-done

	logrus.Info("shutdown")
	os.Exit(0)
}

func newClient(ctx context.Context, config *configure.Config) *Client {
	node := &Client{
		Client: base.NewClient(config),
		http: &fasthttp.Client{
			TLSConfig: utils.TlsConfig(config.SignalServerPublicKey),
		},
		udpLb: loadbalancer.New(),
		tcpLb: loadbalancer.New(),
	}

	go node.HandleTCP(ctx)
	go node.HandleUDP(ctx)

	return node
}

func (c *Client) GetTokens(ctx context.Context, relay string, count int) ([]string, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.Set("mode", "token")
	req.Header.Set("authentication", c.Config.JoinToken)
	req.Header.Set("name", c.Config.Name)
	req.Header.Set("count", strconv.Itoa(count))

	tkns := []string{}

	req.SetRequestURI(fmt.Sprintf("https://%s", relay))

	if err := c.http.Do(req, resp); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(resp.Body(), &tkns); err != nil {
		return nil, err
	}

	return tkns, nil
}

func (c *Client) GetSettings(ctx context.Context, relay string) (HttpSettingsResp, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.Set("mode", "settings")
	req.Header.Set("authentication", c.Config.JoinToken)
	req.Header.Set("name", c.Config.Name)

	settings := HttpSettingsResp{}

	req.SetRequestURI(fmt.Sprintf("https://%s", relay))

	if err := c.http.Do(req, resp); err != nil {
		return settings, err
	}

	if err := json.Unmarshal(resp.Body(), &settings); err != nil {
		return settings, err
	}

	return settings, nil
}

func (c *Client) HandleUDP(ctx context.Context) {
	pc := packet.NewConstructor()

	pingCh := make(chan string, 100)

	handler := func(pc *packet.PacketConstructor, conn net.Conn) {
		pkt := pc.ToPacket()
		switch pkt.Type() {
		case packet.PacketTypeRelayControlPong:
			pingCh <- packet.RelayControlPongPacket(pkt).ID().String()
		case packet.PacketTypeData, packet.PacketTypeExchange, packet.PacketTypePing:
			c.HandlePacket(pc, conn, nil, true, true)
		}
	}

	conns, err := netutil.DialUDP("", c.Config.RelayServer)
	if err != nil {
		logrus.Fatal("failed to dial udp: ", err)
	}

	for _, v := range conns {
		c.udpLb.AddItem(v)
		go func(conn netconn.UDPConn) {
			pc := packet.NewConstructor()

			for {
				_, err := pc.ReadUDP(conn)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					logrus.Warn("error reading udp: ", err)
					continue
				}

				handler(pc, conn)
			}
		}(v)
	}

	tick := time.NewTicker(time.Second * 15)
	first := true

outer:
	for {
		if !first {
			select {
			case <-tick.C:
			case <-pingCh:
				continue outer
			case <-ctx.Done():
				return
			}
		} else {
			first = false
			if ctx.Err() != nil {
				return
			}
		}

		tokens, err := c.GetTokens(ctx, c.Config.RelayServerHttp, 5)
		if err != nil {
			logrus.Errorf("failed to get tokens from: %s - %s", c.Config.RelayServerHttp, err.Error())
			continue outer
		}

		pings := map[string]bool{}

		for i := 0; i < 5; i++ {
			id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
			pings[id.String()] = true
			pc.MakeRelayControlPingPacket(id, utils.OrPanic(hex.DecodeString(tokens[i]))[0].([]byte))
			if _, err := c.udpLb.GetNext().(net.Conn).Write(pc.ToUDP()); err != nil {
				logrus.Error("failed to send packet: ", err)
			}
		}

		timeout := time.After(time.Second * 10)
	timeout:
		for {
			select {
			case ping := <-pingCh:
				if pings[ping] {
					break timeout
				}
			case <-timeout:
				logrus.Warn("failed to refresh udp connection")
				continue outer
			case <-ctx.Done():
				return
			}
		}

		logrus.Info("refreshed udp connection")
	}
}

func (c *Client) HandleTCP(ctx context.Context) {
	first := true

	pc := packet.NewConstructor()

outer:
	for {
		if c.tcpLb != nil {
			for _, v := range c.tcpLb.GetItems() {
				_ = v.(net.Conn).Close()
			}
			c.tcpLb = nil
		}

		if !first {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return
			}
		} else {
			first = false
		}

		if ctx.Err() != nil {
			return
		}

		tokens, err := c.GetTokens(ctx, c.Config.RelayServerHttp, 1)
		if err != nil {
			logrus.Errorf("failed to get tokens from: %s - %v", c.Config.RelayServerHttp, err)
			continue outer
		}

		conns, err := netutil.DialTCP("", c.Config.RelayServer)
		if err != nil {
			logrus.Fatal("failed to dial udp: ", err)
		}

		doneCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		pingCh := make(chan string, 100)

		handler := func(pc *packet.PacketConstructor, conn net.Conn) {
			pkt := pc.ToPacket()
			switch pkt.Type() {
			case packet.PacketTypeRelayControlPong:
				pingCh <- packet.RelayControlPongPacket(pkt).ID().String()
			case packet.PacketTypeData, packet.PacketTypeExchange, packet.PacketTypePing:
				c.HandlePacket(pc, conn, nil, false, true)
			default:
				logrus.Debug("unknown packet", spew.Sdump(pkt))
			}
		}

		lb := loadbalancer.New()
		for _, v := range conns {
			lb.AddItem(v)
			go func(conn net.Conn) {
				pc := packet.NewConstructor()
				defer cancel()

				for {
					err := pc.ReadTCP(conn)
					if err != nil {
						if ctx.Err() != nil {
							return
						}
						logrus.Warn("error reading tcp: ", err)
						return
					}

					handler(pc, conn)
				}
			}(v)
		}

		id := utils.OrPanic(uuid.NewRandom())[0].(uuid.UUID)
		pc.MakeRelayControlPingPacket(id, utils.OrPanic(hex.DecodeString(tokens[0]))[0].([]byte))
		if _, err := lb.GetNext().(net.Conn).Write(pc.ToTCP()); err != nil {
			logrus.Error("failed to send packet: ", err)
		}

		timeout := time.After(time.Second * 10)
	timeout:
		for {
			select {
			case ping := <-pingCh:
				if id.String() == ping {
					break timeout
				}
			case <-timeout:
				logrus.Warn("failed to refresh tcp connection")
				continue outer
			case <-ctx.Done():
				return
			}
		}

		logrus.Info("refreshed tcp connection")

		c.tcpLb = lb

		for {
			select {
			case <-pingCh:
			case <-doneCtx.Done():
				close(pingCh)
				continue outer
			}
		}
	}
}
