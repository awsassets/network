package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/packet"
	"github.com/disembark/network/src/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func Test_RelayClient(t *testing.T) {
	sigPublic := "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----"
	sigPrivate := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	udpConn, err := net.ListenPacket("udp", "127.188.192.1:0")
	assert.ErrorIs(t, err, nil, "Listen to udp packets")
	defer udpConn.Close()
	tcpConn, err := net.Listen("tcp", udpConn.LocalAddr().String())
	assert.ErrorIs(t, err, nil, "Listen to tcp connections")
	defer tcpConn.Close()

	// hash := func(data []byte) string {
	// 	h := sha3.New512()
	// 	h.Write(data)
	// 	return hex.EncodeToString(h.Sum(nil))
	// }

	config := &configure.Config{
		SignalServerPublicKey:  sigPublic,
		SignalServerPrivateKey: sigPrivate,
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Bind:                   "127.188.192.2:0",
		RelayServer:            udpConn.LocalAddr().String(),
		RelayServerHttp:        "127.188.192.1:5555",
		AdvertiseAddresses:     []string{"127.10.101.1"},
	}

	tknStore := sync.Map{}

	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			defer func() {
				if err := recover(); err != nil {
					logrus.Error("panic recovered in http: ", err)
				}
			}()

			tkn, err := helpers.VerifyClientJoinToken(config, utils.B2S(ctx.Request.Header.Peek("authentication")))
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
					tknStore.Store(tkns[i], tkn.Name)
				}

				data, _ := json.Marshal(tkns)

				ctx.SetStatusCode(200)

				ctx.Response.Header.Add("Content-Type", "application/json")
				ctx.Response.Header.Add("Content-Length", strconv.Itoa(len(data)))

				ctx.SetBody(data)
			case "settings":
				data, _ := json.Marshal(HttpSettingsResp{
					AccessPoints: config.AdvertiseAddresses,
				})

				ctx.SetStatusCode(200)

				ctx.Response.Header.Add("Content-Type", "application/json")
				ctx.Response.Header.Add("Content-Length", strconv.Itoa(len(data)))

				ctx.SetBody(data)
			default:
				ctx.SetStatusCode(fasthttp.StatusNotFound)
			}
		},
		Logger:           logrus.New(),
		Name:             "disembark",
		DisableKeepalive: true,
		GetOnly:          true,
		IdleTimeout:      time.Second,
	}

	s.CloseOnShutdown = true
	defer func() {
		_ = s.Shutdown()
	}()

	go func() {
		if err := s.ListenAndServeTLSEmbed("127.188.192.1:5555", utils.S2B(sigPublic), utils.S2B(sigPrivate)); err != nil {
			logrus.Fatal("error in ListenAndServe: ", err)
		}
	}()

	config.MockConfig()

	pub, priv, err := helpers.GenerateClientTls(config)
	assert.ErrorIs(t, err, nil, "Generate a client cert and priv key")
	config.ClientPublicKey = utils.B2S(pub)
	config.ClientPrivateKey = utils.B2S(priv)
	config.JoinToken, err = helpers.GenerateClientJoinToken(config, configure.ModeRelayClient, "test")
	assert.ErrorIs(t, err, nil, "Generate a client join token")

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		pc := packet.NewConstructor()
		for {
			conn, err := tcpConn.Accept()
			if err != nil {
				return
			}
			assert.ErrorIs(t, err, nil, "accept a client")
			for {
				err = pc.ReadTCP(conn)
				if err == io.EOF {
					break
				}

				assert.ErrorIs(t, err, nil, "we read a tcp packet")
				assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")

				pkt := pc.ToPacket()

				assert.Equal(t, packet.PacketTypeRelayControlPing, pkt.Type(), "packet is a control pkt")
				{
					pkt := packet.RelayControlPingPacket(pkt)
					id := pkt.ID()
					token := hex.EncodeToString(pkt.Token())
					name, ok := tknStore.LoadAndDelete(token)
					assert.Equal(t, true, ok, "the token exists")
					assert.Equal(t, config.Name, name, "the name is the same as the config")
					pc.MakeRelayControlPongPacket(id)
					_, err := conn.Write(pc.ToTCP())
					assert.ErrorIs(t, err, nil, "write successful")
				}

				time.Sleep(time.Second)

				// send them a data pkt 👀
				data := make([]byte, packet.MTU)
				{
					_, _ = rand.Read(data)
					pc.MakeDataPacket(data, net.ParseIP("10.10.0.1"))
					_, err := conn.Write(pc.ToTCP())
					assert.ErrorIs(t, err, nil, "write successful")
				}
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		pc := packet.NewConstructor()

		addr, err := pc.ReadUDP(udpConn.(*net.UDPConn))
		if err != nil {
			return
		}
		assert.ErrorIs(t, err, nil, "we read a tcp packet")
		assert.Equal(t, true, pc.ToPacket().Valid(), "The packet is valid")

		pkt := pc.ToPacket()

		assert.Equal(t, packet.PacketTypeRelayControlPing, pkt.Type(), "packet is a control pkt")
		{
			pkt := packet.RelayControlPingPacket(pkt)
			id := pkt.ID()
			token := hex.EncodeToString(pkt.Token())
			name, ok := tknStore.LoadAndDelete(token)
			assert.Equal(t, true, ok, "the token exists")
			assert.Equal(t, config.Name, name, "the name is the same as the config")
			pc.MakeRelayControlPongPacket(id)
			_, err := udpConn.(*net.UDPConn).WriteToUDP(pc.ToUDP(), addr)
			assert.ErrorIs(t, err, nil, "write successful")
		}

		time.Sleep(time.Second)

		data := make([]byte, packet.MTU)
		{
			_, _ = rand.Read(data)
			pc.MakeDataPacket(data, net.ParseIP("10.10.0.1"))
			_, err := udpConn.(*net.UDPConn).WriteToUDP(pc.ToUDP(), addr)
			assert.ErrorIs(t, err, nil, "write successful")
		}
	}()

	node := newClient(ctx, config)
	defer node.Stop()

	_, err = node.GetSettings(context.Background(), config.RelayServerHttp)
	assert.ErrorIs(t, err, nil, "we get the settings")

	wg.Wait()
	time.Sleep(time.Second)
}
