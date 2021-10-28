package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/signal/dhcp"
	"github.com/disembark/network/src/modes/signal/events"
	"github.com/disembark/network/src/modes/signal/node"
	"github.com/disembark/network/src/modes/signal/signals"
	"github.com/disembark/network/src/modes/signal/types"
	"github.com/disembark/network/src/utils"
	"github.com/fasthttp/websocket"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func New(config *configure.Config) {
	if config.SignalServerPrivateKey == "" || config.SignalServerPublicKey == "" {
		types.GenerateCaTls(config)
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
			clConf, err := types.GenerateClient(config, config.CreateName)
			if err != nil {
				logrus.Fatalf("failed to listen: %v", err)
			}
			logrus.Infof("wrote %s with a new node config", clConf.ConfigFile)
		default:
			logrus.Fatal("unknown create mode: ", config.Create)
		}
		return
	}

	gCtx, cancel := context.WithCancel(context.Background())

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(utils.S2B(config.SignalServerPublicKey)); !ok {
		logrus.Fatal("Bad Signal Server Public key")
	}

	wg := &sync.WaitGroup{}
	events := events.New()

	server := &Server{
		ctx:    gCtx,
		dhcp:   dhcp.New(),
		node:   node.New(),
		events: events,
		signal: signals.New(gCtx, config, wg, websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 2 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					certs := make([]*x509.Certificate, len(rawCerts))
					for i, asn1Data := range rawCerts {
						cert, err := x509.ParseCertificate(asn1Data)
						if err != nil {
							return errors.New("tls: failed to parse certificate from server: " + err.Error())
						}
						certs[i] = cert
					}
					opts := x509.VerifyOptions{
						Roots:         rootCAs, // On the server side, use config.ClientCAs.
						Intermediates: x509.NewCertPool(),
					}

					for _, cert := range certs[1:] {
						opts.Intermediates.AddCert(cert)
					}

					_, err := certs[0].Verify(opts)

					return err
				},
			},
		}),
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
		server.signal.Register(v)
	}

	go server.ProcessSignal()

	// Create custom server.
	s := &fasthttp.Server{
		Handler: server.Handler,
		Logger:  logrus.New(),
		Name:    "disembark",
	}

	logrus.Info("starting signal server")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := s.ListenAndServeTLSEmbed(config.Bind, utils.S2B(config.SignalServerPublicKey), utils.S2B(config.SignalServerPrivateKey)); err != nil {
			log.Fatalf("error in ListenAndServe: %s", err)
		}
	}()

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
