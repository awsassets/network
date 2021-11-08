package signal

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/fasthttp/websocket"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type SignalClient struct {
	done chan struct{}
	msgs chan types.Message
	conn *websocket.Conn
}

type Client interface {
	Messages() <-chan types.Message
	Done() <-chan struct{}
	Write(msg types.Message) error
}

type MockSignalClient struct {
	MessagesFunc func() <-chan types.Message
	DoneFunc     func() <-chan struct{}
	WriteFunc    func(msg types.Message) error
}

func (s MockSignalClient) Messages() <-chan types.Message {
	return s.MessagesFunc()
}

func (s MockSignalClient) Done() <-chan struct{} {
	return s.DoneFunc()
}

func (s MockSignalClient) Write(msg types.Message) error {
	return s.WriteFunc(msg)
}

func NewClient(ctx context.Context, config *configure.Config, addrs []string) Client {
	switch config.Mode {
	case configure.ModeNode:
		if config.JoinToken == "" {
			logrus.Fatal("no join token")
		}
	}

	if config.SignalServerPublicKey == "" {
		logrus.Fatal("no signal server public key")
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  utils.TlsConfig(config.SignalServerPublicKey),
	}

	cl := &SignalClient{
		done: make(chan struct{}),
		msgs: make(chan types.Message, 100),
	}

	go func() {
		defer close(cl.done)
		for {
			localCtx, cancel := context.WithCancel(context.Background())
			conn := new(ctx, config, dialer, addrs)
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

func (c *SignalClient) Messages() <-chan types.Message {
	return c.msgs
}

func (c *SignalClient) Done() <-chan struct{} {
	return c.done
}

func (c *SignalClient) Write(msg types.Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return c.conn.WriteMessage(websocket.TextMessage, data)
}

func new(ctx context.Context, config *configure.Config, dialer websocket.Dialer, addrs []string) *websocket.Conn {
	var (
		conn *websocket.Conn
		err  error
	)

	header := http.Header{}

	header.Add("mode", string(config.Mode))

	switch config.Mode {
	case configure.ModeNode, configure.ModeRelayClient:
		header.Add("authentication", config.JoinToken)
		nodePl, _ := json.MarshalToString(types.JoinPayloadNode{
			Name:               config.Name,
			AdvertiseAddresses: addrs,
			DnsAliases:         config.DnsAliases,
			PublicKey:          config.ClientPublicKey,
			IP:                 config.TunBind,
		})
		header.Add("node", nodePl)
	case configure.ModeRelayServer:
		tkn, err := helpers.GenerateClientJoinToken(config, configure.ModeRelayServer, config.Name)
		if err != nil {
			logrus.Fatal("failed to make join token: ", err)
		}

		header.Add("authentication", tkn)
		header.Add("name", config.Name)
	default:
		panic(fmt.Errorf("bad mode for websocket client: %s", config.Mode))
	}

	for {
		for _, v := range config.SignalServers {
			for _, ip := range v.AccessPoints {
				conn, _, err = dialer.Dial(fmt.Sprintf("wss://%s", ip), header)
				if err != nil {
					logrus.Errorf("failed to connect to signal server %s on %s: %s", v.Name, ip, err.Error())
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
