package signal

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	dhcp_store "github.com/disembark/network/src/store/dhcp"
	event_store "github.com/disembark/network/src/store/event"
	node_store "github.com/disembark/network/src/store/node"
	signal_store "github.com/disembark/network/src/store/signal"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/fasthttp/websocket"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type Server struct {
	ctx context.Context

	events event_store.Store
	dhcp   dhcp_store.Store
	node   node_store.Store
	signal signal_store.Store

	wg     *sync.WaitGroup
	config *configure.Config

	nodeConnections   *sync.Map
	signalConnections *sync.Map

	upgrader websocket.FastHTTPUpgrader
}

func NewServer(config *configure.Config) {
	if config.SignalServerPrivateKey == "" || config.SignalServerPublicKey == "" {
		helpers.GenerateCaTls(config)
		if err := config.Save(); err != nil {
			logrus.Fatalf("Failed to generate private key: %v", err)
		}
	}

	if len(config.TokenKey) == 0 {
		config.TokenKey = hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte))
		if err := config.Save(); err != nil {
			logrus.Fatalf("failed to listen: %v", err)
		}
	}

	if config.Create != "" {
		switch config.Create {
		case configure.ModeNode:
			clConf, err := helpers.GenerateNode(config, config.CreateName)
			if err != nil {
				logrus.Fatalf("failed to listen: %v", err)
			}
			if err = clConf.Save(); err != nil {
				logrus.Fatal("failed to save config: ", err)
			}
			logrus.Infof("wrote %s with a new node config", clConf.Config)
		case configure.ModeSignal:
			clConf, err := helpers.GenerateSignal(config, config.CreateName)
			if err != nil {
				logrus.Fatalf("failed to listen: %v", err)
			}
			if err = clConf.Save(); err != nil {
				logrus.Fatal("failed to save config: ", err)
			}
			logrus.Infof("wrote %s with a new signal config", clConf.Config)
		case configure.ModeRelayServer:
			clConf, err := helpers.GenerateRelayServer(config, config.CreateName)
			if err != nil {
				logrus.Fatalf("failed to listen: %v", err)
			}
			if err = clConf.Save(); err != nil {
				logrus.Fatal("failed to save config: ", err)
			}
			logrus.Infof("wrote %s with a new relay server config", clConf.Config)
		case configure.ModeRelayClient:
			clConf, err := helpers.GenerateRelayClient(config, config.CreateName)
			if err != nil {
				logrus.Fatalf("failed to listen: %v", err)
			}
			if err = clConf.Save(); err != nil {
				logrus.Fatal("failed to save config: ", err)
			}
			logrus.Infof("wrote %s with a new relay client config", clConf.Config)
		default:
			logrus.Fatal("unknown create mode: ", config.Create)
		}
		return
	}

	logrus.Info("starting signal server")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	server := newServer(ctx, config)

	server.signal = signal_store.New(ctx, config, server.wg, websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  utils.TlsConfig(config.SignalServerPublicKey),
	})
	go server.ProcessSignal()

	done := make(chan struct{})

	go func() {
		<-c
		cancel()
		go func() {
			select {
			case <-c:
			case <-time.After(time.Minute):
			}
			logrus.Fatal("force shutdown")
		}()
		logrus.Info("shutting down")
		server.wg.Wait()
		close(done)
	}()

	<-done
	logrus.Info("shutdown")
	os.Exit(0)
}

func newServer(ctx context.Context, config *configure.Config) *Server {
	wg := &sync.WaitGroup{}
	events := event_store.New()

	server := &Server{
		ctx:    ctx,
		dhcp:   dhcp_store.New(),
		node:   node_store.New(),
		events: events,

		wg:                wg,
		config:            config,
		nodeConnections:   &sync.Map{},
		signalConnections: &sync.Map{},
		upgrader: websocket.FastHTTPUpgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}

	for _, v := range config.SignalServers {
		tkn, err := helpers.GenerateClientJoinToken(config, configure.ModeSignal, config.Name)
		if err != nil {
			logrus.Fatal("failed to generate join token: ", err)
		}

		server.signal.Register(v, tkn)
	}

	// Create custom server.
	s := &fasthttp.Server{
		Handler: server.Handler,
		Logger:  logrus.New(),
		Name:    "disembark",
	}

	go func() {
		if err := s.ListenAndServeTLSEmbed(config.Bind, utils.S2B(config.SignalServerPublicKey), utils.S2B(config.SignalServerPrivateKey)); err != nil {
			logrus.Fatal("error in ListenAndServe: ", err)
		}
	}()

	return server
}

func (s *Server) ProcessSignal() {
	// reading messages
	go func() {
		msgs := s.signal.Messages()
		for msg := range msgs {
			spew.Dump(msg)
		}
	}()
	// writing messages
	conns := s.signal.Conns()
	for conn := range conns {
		id, _ := uuid.NewRandom()
		s.events.Register(id.String())
		_ = s.signal.Write(conn, types.Message{
			Type: types.MessageTypeSignalRegister,
			Payload: utils.OrPanic(json.Marshal(types.MessageSignalRegister{
				Signal: types.MessageSignalState{
					SignalServer: configure.SignalServer{
						Name:         s.config.Name,
						AccessPoints: s.config.AdvertiseAddresses,
					},
					Nodes:   s.node.Serialize(),
					DHCP:    s.dhcp.Serialize(),
					Signals: s.config.SignalServers,
				},
			}))[0].([]byte),
			Key: id.String(),
		})
	}
}
