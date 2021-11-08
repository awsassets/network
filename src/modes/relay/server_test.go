package relay

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/modes/signal"
	"github.com/disembark/network/src/packet"
	node_store "github.com/disembark/network/src/store/node"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func setupServer(t *testing.T, bind string) *Server {
	sigPublic := "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----"
	sigPrivate := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----"

	config := &configure.Config{
		SignalServerPublicKey:  sigPublic,
		SignalServerPrivateKey: sigPrivate,
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Bind:                   "127.0.0.1:0",
		RelayHttpBind:          bind,
		AdvertiseAddresses:     []string{"127.10.101.1"},
	}

	jt, err := helpers.GenerateClientJoinToken(config, configure.ModeRelayClient, "test")
	assert.ErrorIs(t, err, nil, "join token is made")

	config.JoinToken = jt

	return newServer(config)
}

func Test_ServerHttp(t *testing.T) {
	server := setupServer(t, "127.1.222.111:5555")
	defer server.Stop()

	httpClient := &fasthttp.Client{
		TLSConfig: utils.TlsConfig(server.config.SignalServerPublicKey),
	}

	time.Sleep(time.Second)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.Header.Set("name", "test")
	req.Header.Set("authentication", server.config.JoinToken)
	req.Header.Set("mode", "settings")
	req.SetRequestURI("https://127.1.222.111:5555")

	err := httpClient.Do(req, resp)
	assert.ErrorIs(t, err, nil, "request is done")

	settings := HttpSettingsResp{}
	err = json.Unmarshal(resp.Body(), &settings)
	assert.ErrorIs(t, err, nil, "valid json")

	assert.Equal(t, 1, len(settings.AccessPoints), "1 access point")
	assert.Equal(t, server.config.AdvertiseAddresses[0], settings.AccessPoints[0], "1 access point")

	req.Header.Set("mode", "token")
	req.Header.Set("count", "5")

	err = httpClient.Do(req, resp)
	assert.ErrorIs(t, err, nil, "request is done")

	tokens := []string{}
	err = json.Unmarshal(resp.Body(), &tokens)
	assert.ErrorIs(t, err, nil, "valid json")
	assert.Equal(t, 5, len(tokens), "5 tokens")
}

func Test_ServerProcessSignal(t *testing.T) {
	server := setupServer(t, "127.1.222.111:0")
	defer server.Stop()

	messageCh := make(chan types.Message)
	doneCh := make(chan struct{})
	writeCh := make(chan types.Message, 100)
	server.client = &signal.MockSignalClient{
		MessagesFunc: func() <-chan types.Message {
			return messageCh
		},
		DoneFunc: func() <-chan struct{} {
			return doneCh
		},
		WriteFunc: func(msg types.Message) error {
			writeCh <- msg
			return nil
		},
	}

	go server.ProcessSignal()
	messageCh <- types.Message{
		Type: types.MessageTypeNodeState,
		Payload: utils.OrPanic(json.Marshal(types.MessageNodeState{
			Current: types.JoinPayloadNode{
				IP: "10.10.0.1",
			},
		}))[0].([]byte),
	}

	messageCh <- types.Message{
		Type: types.MessageTypeNodeRegister,
		Payload: utils.OrPanic(json.Marshal(types.MessageNodeRegister{
			Node: types.JoinPayloadNode{
				Name: "test",
				IP:   "10.10.0.2",
			},
		}))[0].([]byte),
	}

	messageCh <- types.Message{
		Type: types.MessageTypeSignalRegister,
		Payload: utils.OrPanic(json.Marshal(types.MessageSignalRegister{
			Signal: types.MessageSignalState{
				SignalServer: configure.SignalServer{
					Name: "batcchest",
				},
			},
		}))[0].([]byte),
	}

	messageCh <- types.Message{
		Type: types.MessageTypeSignalRegister,
		Payload: utils.OrPanic(json.Marshal(types.MessageSignalRegister{
			Signal: types.MessageSignalState{
				SignalServer: configure.SignalServer{
					Name: "batchest",
					AccessPoints: []string{
						"pogu",
					},
				},
				Signals: []configure.SignalServer{
					{
						Name: "batcchest2",
						AccessPoints: []string{
							"pogu2",
						},
					}, {
						Name: "batcchest3",
					},
				},
			},
		}))[0].([]byte),
	}

	messageCh <- types.Message{
		Type: types.MessageTypeSignalRegister,
		Payload: utils.OrPanic(json.Marshal(types.MessageSignalRegister{
			Signal: types.MessageSignalState{
				SignalServer: configure.SignalServer{
					Name: "batcchest",
				},
				Signals: []configure.SignalServer{
					{
						Name: "batcchest2",
						AccessPoints: []string{
							"pogu2",
						},
					}, {
						Name: "batcchest3",
					},
				},
			},
		}))[0].([]byte),
	}
}

func Test_ServerConn(t *testing.T) {
	server := setupServer(t, "127.1.222.111:0")
	defer server.Stop()

	udpConn, err := net.Dial("udp", server.udpConns[0].LocalAddr().String())
	assert.ErrorIs(t, err, nil, "request is done")

	tcpConn, err := net.Dial("tcp", server.tcpConns[0].Addr().String())
	assert.ErrorIs(t, err, nil, "request is done")

	udpConn2, err := net.Dial("udp", server.udpConns[0].LocalAddr().String())
	assert.ErrorIs(t, err, nil, "request is done")

	tcpConn2, err := net.Dial("tcp", server.tcpConns[0].Addr().String())
	assert.ErrorIs(t, err, nil, "request is done")

	server.nodes.SetNode("test", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name:  "test",
			IP:    "10.10.0.1",
			Relay: true,
		},
	})

	server.nodes.SetNode("test2", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name:  "test2",
			IP:    "10.10.0.2",
			Relay: true,
		},
	})

	pc := packet.NewConstructor()

	// udp 1
	{
		tkn := hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte))
		server.tokenStore.Store(tkn, "test")
		id, _ := uuid.NewRandom()
		btkn, _ := hex.DecodeString(tkn)
		pc.MakeRelayControlPingPacket(id, btkn)

		_, err = udpConn.Write(pc.ToUDP())
		assert.ErrorIs(t, err, nil, "request is done")

		_, err = pc.ReadUDP(udpConn.(*net.UDPConn))
		assert.ErrorIs(t, err, nil, "we get a response")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
		assert.Equal(t, packet.PacketTypeRelayControlPong, pc.ToPacket().Type(), "the packet is a relay control pong packet")
		pkt := packet.RelayControlPongPacket(pc.ToPacket())

		assert.Equal(t, pkt.ID(), id, "the pong is correct")
	}
	// tcp 1
	{
		tkn := hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte))
		server.tokenStore.Store(tkn, "test")
		id, _ := uuid.NewRandom()
		btkn, _ := hex.DecodeString(tkn)
		pc.MakeRelayControlPingPacket(id, btkn)

		_, err = tcpConn.Write(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "request is done")

		err = pc.ReadTCP(tcpConn)
		assert.ErrorIs(t, err, nil, "we get a response")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
		assert.Equal(t, packet.PacketTypeRelayControlPong, pc.ToPacket().Type(), "the packet is a relay control pong packet")
		pkt := packet.RelayControlPongPacket(pc.ToPacket())

		assert.Equal(t, pkt.ID(), id, "the pong is correct")
	}

	// udp 2
	{
		tkn := hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte))
		server.tokenStore.Store(tkn, "test2")
		id, _ := uuid.NewRandom()
		btkn, _ := hex.DecodeString(tkn)
		pc.MakeRelayControlPingPacket(id, btkn)

		_, err = udpConn2.Write(pc.ToUDP())
		assert.ErrorIs(t, err, nil, "request is done")

		_, err = pc.ReadUDP(udpConn2.(*net.UDPConn))
		assert.ErrorIs(t, err, nil, "we get a response")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
		assert.Equal(t, packet.PacketTypeRelayControlPong, pc.ToPacket().Type(), "the packet is a relay control pong packet")
		pkt := packet.RelayControlPongPacket(pc.ToPacket())

		assert.Equal(t, pkt.ID(), id, "the pong is correct")
	}
	//tcp 2
	{
		tkn := hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte))
		server.tokenStore.Store(tkn, "test2")
		id, _ := uuid.NewRandom()
		btkn, _ := hex.DecodeString(tkn)
		pc.MakeRelayControlPingPacket(id, btkn)

		_, err = tcpConn2.Write(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "request is done")

		err = pc.ReadTCP(tcpConn2)
		assert.ErrorIs(t, err, nil, "we get a response")

		assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
		assert.Equal(t, packet.PacketTypeRelayControlPong, pc.ToPacket().Type(), "the packet is a relay control pong packet")
		pkt := packet.RelayControlPongPacket(pc.ToPacket())

		assert.Equal(t, pkt.ID(), id, "the pong is correct")
	}

	// send ping to other node BASED
	// tcp ping 1 -> 2
	{
		id, _ := uuid.NewRandom()
		pc.MakeRelayPingPacket(id, net.ParseIP("10.10.0.1"), net.ParseIP("10.10.0.2"))
		_, err = tcpConn.Write(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "we write a ping packet to the other node")

		{
			err = pc.ReadTCP(tcpConn2)
			assert.ErrorIs(t, err, nil, "we read a ping packet from the other node")
			assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
			assert.Equal(t, packet.PacketTypePing, pc.ToPacket().Type(), "the packet is a ping packet")
			pkt := packet.PingPacket(pc.ToPacket())
			assert.Equal(t, id, pkt.ID(), "the ping id is preserved")
			assert.Equal(t, net.ParseIP("10.10.0.1").To4(), pkt.IP().To4(), "The ip is the other node")

			pc.MakeRelayPongPacket(id, pkt.IP())
			_, err = tcpConn2.Write(pc.ToTCP())
			assert.ErrorIs(t, err, nil, "we write a pong packet from the other node")

			{
				err = pc.ReadTCP(tcpConn)
				assert.ErrorIs(t, err, nil, "we read a pong packet from the other node")
				assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
				assert.Equal(t, packet.PacketTypePong, pc.ToPacket().Type(), "the packet is a pong packet")
				pkt := packet.PongPacket(pc.ToPacket())
				assert.Equal(t, id, pkt.ID(), "the ping id is preserved")
			}
		}
	}
	// tcp ping 2 -> 1
	{
		id, _ := uuid.NewRandom()
		pc.MakeRelayPingPacket(id, net.ParseIP("10.10.0.2"), net.ParseIP("10.10.0.1"))
		_, err = udpConn2.Write(pc.ToUDP())
		assert.ErrorIs(t, err, nil, "we write a ping packet to the other node")

		{
			_, err = pc.ReadUDP(udpConn.(*net.UDPConn))
			assert.ErrorIs(t, err, nil, "we read a ping packet from the other node")
			assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
			assert.Equal(t, packet.PacketTypePing, pc.ToPacket().Type(), "the packet is a ping packet")
			pkt := packet.PingPacket(pc.ToPacket())
			assert.Equal(t, id, pkt.ID(), "the ping id is preserved")
			assert.Equal(t, net.ParseIP("10.10.0.2").To4(), pkt.IP().To4(), "The ip is the other node")

			pc.MakeRelayPongPacket(id, pkt.IP())
			_, err = udpConn.Write(pc.ToUDP())
			assert.ErrorIs(t, err, nil, "we write a pong packet from the other node")

			{
				_, err = pc.ReadUDP(udpConn2.(*net.UDPConn))
				assert.ErrorIs(t, err, nil, "we read a pong packet from the other node")
				assert.Equal(t, true, pc.ToPacket().Valid(), "the packet is valid")
				assert.Equal(t, packet.PacketTypePong, pc.ToPacket().Type(), "the packet is a pong packet")
				pkt := packet.PongPacket(pc.ToPacket())
				assert.Equal(t, id, pkt.ID(), "the ping id is preserved")
			}
		}
	}

	time.Sleep(time.Second)
}
