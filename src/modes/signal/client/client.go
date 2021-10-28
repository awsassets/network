package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/signal/types"
	"github.com/disembark/network/src/utils"
	"github.com/fasthttp/websocket"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type Client struct {
	done chan struct{}
	msgs chan types.Message
	conn *websocket.Conn
}

func New(ctx context.Context, config *configure.Config) *Client {
	if config.JoinToken == "" {
		logrus.Fatal("no join token")
	}

	if config.SignalServerPublicKey == "" {
		logrus.Fatal("no signal server public key")
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(utils.S2B(config.SignalServerPublicKey)); !ok {
		logrus.Fatal("Bad Signal Server Public key")
	}

	dialer := websocket.Dialer{
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
	}

	cl := &Client{
		done: make(chan struct{}),
		msgs: make(chan types.Message, 100),
	}

	go func() {
		defer close(cl.done)
		for {
			localCtx, cancel := context.WithCancel(context.Background())
			conn := new(ctx, config, dialer)
			cl.conn = conn
			if conn == nil || ctx.Err() != nil {
				cancel()
				return
			}
			go func() {
				defer cancel()
				var msg types.Message
				for {
					_, d, err := conn.ReadMessage()
					if err != nil {
						return
					}
					if err := json.Unmarshal(d, &msg); err != nil {
						logrus.Warn("bad message: ", err)
						continue
					}
					cl.msgs <- msg
				}
			}()
			go func() {
				<-ctx.Done()
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1000, "shutting down"), time.Now().Add(time.Second*10))
				_ = conn.Close()
			}()
			<-localCtx.Done()
			if ctx.Err() != nil {
				return
			}
		}
	}()

	return cl
}

func (c *Client) Messages() <-chan types.Message {
	return c.msgs
}

func (c *Client) Done() <-chan struct{} {
	return c.done
}

func (c *Client) Write(msg types.Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return c.conn.WriteMessage(websocket.TextMessage, data)
}

func new(ctx context.Context, config *configure.Config, dialer websocket.Dialer) *websocket.Conn {
	var (
		conn *websocket.Conn
		err  error
	)

	header := http.Header{}
	header.Add("mode", "node")
	header.Add("authentication", config.JoinToken)
	nodePl, _ := json.MarshalToString(types.JoinPayloadNode{
		Name:               config.Name,
		AdvertiseAddresses: config.AdvertiseAddresses,
		DnsAliases:         config.DnsAliases,
		PublicKey:          config.ClientPublicKey,
		IP:                 config.TunBind,
	})
	header.Add("node", nodePl)

	for {
		for _, v := range config.SignalServers {
			for _, ip := range v.AccessPoints {
				conn, _, err = dialer.Dial(fmt.Sprintf("wss://%s", ip), header)
				if err != nil {
					logrus.Errorf("failed to connect to signal server %s on %s: %e", v.Name, ip, err)
				} else {
					logrus.Infof("connected to signal server %s on %s", v.Name, ip)
					return conn
				}
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					return nil
				}
			}
		}
		select {
		case <-time.After(time.Second * 5):
		case <-ctx.Done():
			return nil
		}
	}
}
