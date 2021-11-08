package signal_store

import (
	"context"
	"encoding/hex"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/fasthttp/websocket"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func Test_Signal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
	}

	wg := &sync.WaitGroup{}

	signal := New(ctx, config, wg, websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  utils.TlsConfig(config.SignalServerPublicKey),
	})

	// events := event_store.New()

	connCh := signal.Conns()
	msgCh := signal.Messages()

	up := websocket.FastHTTPUpgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	success := make(chan bool)

	testMsg := types.Message{
		Type: types.MessageTypePong,
		Key:  "poggers",
	}

	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			mode := configure.Mode(utils.B2S(ctx.Request.Header.Peek("mode")))
			assert.Equal(t, configure.ModeSignal, mode, "mode is signal")

			tkn, err := helpers.VerifyClientJoinToken(config, utils.B2S(ctx.Request.Header.Peek("authentication")))
			assert.ErrorIs(t, err, nil, "no error when verifying token")

			assert.Equal(t, tkn.Name, config.Name, "name is name")
			assert.Equal(t, tkn.Mode, configure.ModeSignal, "mode is signal")

			var msg types.Message
			err = up.Upgrade(ctx, func(c *websocket.Conn) {
				dt, v, err := c.ReadMessage()
				assert.ErrorIs(t, err, nil, "no error reading message")

				err = json.Unmarshal(v, &msg)
				assert.ErrorIs(t, err, nil, "no error unmarshal message")

				assert.Equal(t, testMsg, msg, "message is the same")

				err = c.WriteMessage(dt, v)
				assert.ErrorIs(t, err, nil, "no error writing message")

				dt, v, err = c.ReadMessage()
				assert.ErrorIs(t, err, nil, "no error reading message")

				err = json.Unmarshal(v, &msg)
				assert.ErrorIs(t, err, nil, "no error unmarshal message")

				assert.Equal(t, testMsg, msg, "message is the same")

				err = c.WriteMessage(dt, v)
				assert.ErrorIs(t, err, nil, "no error writing message")

				success <- true
			})
			assert.ErrorIs(t, err, nil, "No error when upgrading connection")
		},
		Logger: logrus.New(),
		Name:   "disembark",
	}

	go func() {
		if err := s.ListenAndServeTLSEmbed("127.0.0.123:8888", utils.S2B(config.SignalServerPublicKey), utils.S2B(config.SignalServerPrivateKey)); err != nil {
			logrus.Fatal("error in ListenAndServe: ", err)
		}
	}()

	tkn, err := helpers.GenerateClientJoinToken(config, configure.ModeSignal, config.Name)
	assert.ErrorIs(t, err, nil, "no error generating config")

	name := "pog"
	signal.Register(configure.SignalServer{
		Name:         name,
		AccessPoints: []string{"127.0.0.123:8888"},
	}, tkn)

	signal.Register(configure.SignalServer{
		Name:         name,
		AccessPoints: []string{"127.0.0.123:8888"},
	}, tkn)

	assert.Equal(t, name, <-connCh, "signal server registered")

	signal.Broadcast(testMsg)
	msg := <-msgCh
	assert.Equal(t, name, msg.Node, "node is name")
	assert.Equal(t, testMsg, msg.Msg, "message is the same")

	err = signal.Write(name, testMsg)
	assert.ErrorIs(t, err, nil, "No error when writing a packet")
	msg = <-msgCh
	assert.Equal(t, name, msg.Node, "node is name")
	assert.Equal(t, testMsg, msg.Msg, "message is the same")

	<-success
}
