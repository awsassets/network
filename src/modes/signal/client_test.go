package signal

import (
	"context"
	"encoding/hex"
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

func Test_ClientNode(t *testing.T) {
	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Mode:                   configure.ModeNode,
		SignalServers: []configure.SignalServer{{
			Name:         "based",
			AccessPoints: []string{"127.0.122.123:8888"},
		}},
	}

	jt, err := helpers.GenerateClientJoinToken(config, configure.ModeNode, "test")
	assert.ErrorIs(t, err, nil, "create a join token")

	config.JoinToken = jt

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			assert.Equal(t, configure.ModeNode, mode, "mode is node")

			tkn, err := helpers.VerifyClientJoinToken(config, utils.B2S(ctx.Request.Header.Peek("authentication")))
			assert.ErrorIs(t, err, nil, "no error when verifying token")

			assert.Equal(t, tkn.Name, config.Name, "name is name")
			assert.Equal(t, tkn.Mode, configure.ModeNode, "mode is signal")

			var msg types.Message
			err = up.Upgrade(ctx, func(c *websocket.Conn) {
				success <- true

				dt, v, err := c.ReadMessage()
				assert.ErrorIs(t, err, nil, "no error reading message")

				err = json.Unmarshal(v, &msg)
				assert.ErrorIs(t, err, nil, "no error unmarshal message")

				assert.Equal(t, testMsg, msg, "message is the same")

				err = c.WriteMessage(dt, v)
				assert.ErrorIs(t, err, nil, "no error writing message")

				success <- true

				<-success
			})
			assert.ErrorIs(t, err, nil, "No error when upgrading connection")
		},
		Logger: logrus.New(),
		Name:   "disembark",
	}

	go func() {
		if err := s.ListenAndServeTLSEmbed("127.0.122.123:8888", utils.S2B(config.SignalServerPublicKey), utils.S2B(config.SignalServerPrivateKey)); err != nil {
			logrus.Fatal("error in ListenAndServe: ", err)
		}
	}()

	client := NewClient(ctx, config, config.AdvertiseAddresses)

	<-success

	time.Sleep(time.Second)

	err = client.Write(testMsg)
	assert.ErrorIs(t, err, nil, "No error when sending messages")

	<-success

	msg := <-client.Messages()

	assert.Equal(t, testMsg, msg, "message is the same")

	success <- true
}

func Test_ClientRelay(t *testing.T) {
	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Mode:                   configure.ModeRelayServer,
		SignalServers: []configure.SignalServer{{
			Name:         "based",
			AccessPoints: []string{"127.0.0.123:8889"},
		}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			assert.Equal(t, configure.ModeRelayServer, mode, "mode is node")

			tkn, err := helpers.VerifyClientJoinToken(config, utils.B2S(ctx.Request.Header.Peek("authentication")))
			assert.ErrorIs(t, err, nil, "no error when verifying token")

			assert.Equal(t, tkn.Name, config.Name, "name is name")
			assert.Equal(t, tkn.Mode, configure.ModeRelayServer, "mode is relay server")

			var msg types.Message
			err = up.Upgrade(ctx, func(c *websocket.Conn) {
				success <- true

				dt, v, err := c.ReadMessage()
				assert.ErrorIs(t, err, nil, "no error reading message")

				err = json.Unmarshal(v, &msg)
				assert.ErrorIs(t, err, nil, "no error unmarshal message")

				assert.Equal(t, testMsg, msg, "message is the same")

				err = c.WriteMessage(dt, v)
				assert.ErrorIs(t, err, nil, "no error writing message")

				success <- true

				<-success
			})
			assert.ErrorIs(t, err, nil, "No error when upgrading connection")
		},
		Logger: logrus.New(),
		Name:   "disembark",
	}

	go func() {
		if err := s.ListenAndServeTLSEmbed("127.0.0.123:8889", utils.S2B(config.SignalServerPublicKey), utils.S2B(config.SignalServerPrivateKey)); err != nil {
			logrus.Fatal("error in ListenAndServe: ", err)
		}
	}()

	client := NewClient(ctx, config, config.AdvertiseAddresses)

	<-success
	time.Sleep(time.Second)

	err := client.Write(testMsg)
	assert.ErrorIs(t, err, nil, "No error when sending messages")

	<-success

	msg := <-client.Messages()

	assert.Equal(t, testMsg, msg, "message is the same")

	success <- true
}
