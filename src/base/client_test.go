package base

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"testing"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/modes/signal"
	"github.com/disembark/network/src/netconn"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/packet"
	aes_store "github.com/disembark/network/src/store/aes"
	conn_store "github.com/disembark/network/src/store/conn"
	node_store "github.com/disembark/network/src/store/node"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/go-ping/ping"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water/waterutil"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func setupClient(t *testing.T) *Client {
	logrus.SetLevel(logrus.TraceLevel)

	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
	}

	config.MockConfig()

	pub, priv, err := helpers.GenerateClientTls(config)
	assert.ErrorIs(t, err, nil, "Generate a client cert and priv key")
	config.ClientPublicKey = utils.B2S(pub)
	config.ClientPrivateKey = utils.B2S(priv)

	return NewClient(config)
}

func Test_ClientSignal(t *testing.T) {
	client := setupClient(t)
	defer client.Stop()

	otherIP := "10.10.0.2"

	messageCh := make(chan types.Message)
	doneCh := make(chan struct{})
	writeCh := make(chan types.Message, 100)
	client.SignalClient = &signal.MockSignalClient{
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

	go client.ProcessSignal()
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
				IP:   otherIP,
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

	time.Sleep(time.Second)

	client.Stop()
}

func Test_ClientHandlePacket(t *testing.T) {
	client := setupClient(t)
	defer client.Stop()

	otherIP := "10.10.0.2"
	var err error

	client.NodeStore.SetNode("test", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "test",
			IP:   otherIP,
		},
	})

	pc := packet.NewConstructor()

	pktTcpCh := make(chan []byte, 100)
	pktUdpCh := make(chan []byte, 100)
	defer close(pktTcpCh)
	defer close(pktUdpCh)

	mockUDPConn := netconn.MockUDPConn{
		ReadFromUDPFunc: func(b []byte) (int, *net.UDPAddr, error) {
			pkt, ok := <-pktUdpCh
			if !ok {
				return 0, nil, io.EOF
			}
			return copy(b, pkt), nil, nil
		},
		WriteToUDPFunc: func(b []byte, addr *net.UDPAddr) (int, error) {
			pktUdpCh <- b
			return len(b), nil
		},
		MockConn: netconn.MockConn{
			WriteFunc: func(b []byte) (n int, err error) {
				pktUdpCh <- b
				return len(b), nil
			},
			ReadFunc: func(b []byte) (n int, err error) {
				pkt, ok := <-pktUdpCh
				if !ok {
					return 0, io.EOF
				}
				return copy(b, pkt), nil
			},
			CloseFunc: func() error {
				return nil
			},
		},
	}

	mockTCPConn := netconn.MockConn{
		WriteFunc: func(b []byte) (n int, err error) {
			pktTcpCh <- b
			return len(b), nil
		},
		ReadFunc: func(b []byte) (n int, err error) {
			pkt := <-pktTcpCh
			return copy(b, pkt), nil
		},
		CloseFunc: func() error {
			return nil
		},
	}

	mockTCPConnReader := bufio.NewReader(mockTCPConn)

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockTCPConn, nil, false, false)

		err = pc.ReadTCP(mockTCPConnReader)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypePong, pkt.Type(), "Packet is a pong packet")
		{
			pkt := packet.PongPacket(pkt)
			assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
		}
	}

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockUDPConn, nil, true, false)

		_, err = pc.ReadUDP(mockUDPConn)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypePong, pkt.Type(), "Packet is a pong packet")
		{
			pkt := packet.PongPacket(pkt)
			assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
		}
	}

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockUDPConn, &net.UDPAddr{}, true, false)

		_, err = pc.ReadUDP(mockUDPConn)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypePong, pkt.Type(), "Packet is a pong packet")
		{
			pkt := packet.PongPacket(pkt)
			assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
		}
	}

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockUDPConn, nil, true, true)

		_, err = pc.ReadUDP(mockUDPConn)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypeRelay, pkt.Type(), "Packet is a relay packet")
		{
			pkt := packet.RelayPacket(pkt).ToPacket()
			assert.Equal(t, packet.PacketTypePong, pkt.Type(), "Packet is a pong packet")
			{
				pkt := packet.PongPacket(pkt)
				assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
			}
		}
	}

	aesKey := aes_store.AesKey{
		KeyBytes: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}

	{
		data := make([]byte, packet.MTU+aes_store.BlockSize)

		_, _ = rand.Read(data[aes_store.BlockSize:])

		data, err := aesKey.Encrypt(data)
		assert.ErrorIs(t, err, nil, "no error when encrypting data")

		pc.MakeDataPacket(data, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockTCPConn, nil, false, false)
	}

	{
		b, _ := pem.Decode(utils.S2B(client.Config.ClientPublicKey))
		cert, _ := x509.ParseCertificate(b.Bytes)
		public := ecies.ImportECDSAPublic(cert.PublicKey.(*ecdsa.PublicKey))
		encrypted, err := ecies.Encrypt(rand.Reader, public, aesKey.KeyRaw(), nil, nil)
		if err != nil {
			logrus.Fatal("failed to encrypt data: ", err)
		}

		pc.MakeExchangePacket(encrypted, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockUDPConn, nil, true, false)
	}

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockTCPConn, nil, false, false)

		err = pc.ReadTCP(mockTCPConnReader)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypePongAes, pkt.Type(), "Packet is a pong aes packet")
		{
			pkt := packet.PongAesPacket(pkt)
			assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
			h := hmac.New(sha3.New512, aesKey.KeyRaw())
			h.Write(pkt.Data())

			assert.Equal(t, true, hmac.Equal(h.Sum(nil), pkt.Hmac()), "The pong packet is valid")
		}
	}

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockTCPConn, nil, false, true)

		err = pc.ReadTCP(mockTCPConnReader)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypeRelay, pkt.Type(), "Packet is a relay packet")
		{
			pkt := packet.RelayPacket(pkt).ToPacket()
			assert.Equal(t, packet.PacketTypePongAes, pkt.Type(), "Packet is a pong aes packet")
			{
				pkt := packet.PongAesPacket(pkt)
				assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
				h := hmac.New(sha3.New512, aesKey.KeyRaw())
				h.Write(pkt.Data())

				assert.Equal(t, true, hmac.Equal(h.Sum(nil), pkt.Hmac()), "The pong packet is valid")
			}
		}
	}

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockUDPConn, nil, true, false)

		_, err = pc.ReadUDP(mockUDPConn)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypePongAes, pkt.Type(), "Packet is a pong aes packet")
		{
			pkt := packet.PongAesPacket(pkt)
			assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
			h := hmac.New(sha3.New512, aesKey.KeyRaw())
			h.Write(pkt.Data())

			assert.Equal(t, true, hmac.Equal(h.Sum(nil), pkt.Hmac()), "The pong packet is valid")
		}
	}

	{
		id, _ := uuid.NewRandom()

		pc.MakePingPacket(id, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockUDPConn, &net.UDPAddr{}, true, false)

		_, err = pc.ReadUDP(mockUDPConn)
		assert.ErrorIs(t, err, nil, "no error when reading tcp packets")
		pkt := pc.ToPacket()
		assert.Equal(t, true, pkt.Valid(), "Packet is valid")
		assert.Equal(t, packet.PacketTypePongAes, pkt.Type(), "Packet is a pong aes packet")
		{
			pkt := packet.PongAesPacket(pkt)
			assert.Equal(t, id, pkt.ID(), "pong packet is for the correct id")
			h := hmac.New(sha3.New512, aesKey.KeyRaw())
			h.Write(pkt.Data())

			assert.Equal(t, true, hmac.Equal(h.Sum(nil), pkt.Hmac()), "The pong packet is valid")
		}
	}

	{
		data := make([]byte, packet.MTU+aes_store.BlockSize)

		_, _ = rand.Read(data[aes_store.BlockSize:])

		data, err := aesKey.Encrypt(data)
		assert.ErrorIs(t, err, nil, "no error when encrypting data")

		pc.MakeDataPacket(data, net.ParseIP(otherIP))

		client.HandlePacket(pc, mockTCPConn, nil, false, false)
	}

	client.Stop()
}

func Test_ClientProcessDevice(t *testing.T) {
	client := setupClient(t)
	defer client.Stop()

	otherIP := "10.10.0.2"
	*client.IP = "10.10.0.1"
	client.Network.SetIP("10.10.0.1")

	client.NodeStore.SetNode("test", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "test",
			IP:   otherIP,
		},
	})

	serverAesKey := aes_store.AesKey{
		KeyBytes: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}

	testAesKey, _ := client.AesStore.GetOrNew("test")

	udpChan := make(chan []byte, 100)
	tcpChan := make(chan []byte, 100)
	defer close(udpChan)
	defer close(tcpChan)

	client.ConnStore = conn_store.MockConnStore{
		NewFunc: func(ip string) conn_store.Conn {
			_, ok := client.NodeStore.GetNode(ip)
			if !ok {
				return nil
			}

			return conn_store.MockConnInstance{
				AesFunc: func() aes_store.Key {
					return serverAesKey
				},
				WriteUDPFunc: func(pkt packet.TcpPacket) error {
					udpChan <- pkt.ToPacket()
					return nil
				},
				WriteTCPFunc: func(pkt packet.TcpPacket) error {
					tcpChan <- pkt
					return nil
				},
			}
		},
	}

	pinger, err := ping.NewPinger("10.10.0.2")
	assert.ErrorIs(t, err, nil, "no errors when sending pings")
	pinger.Count = 1

	go func() {
		mockUDPConn := netconn.MockUDPConn{
			ReadFromUDPFunc: func(b []byte) (int, *net.UDPAddr, error) {
				pkt, ok := <-udpChan
				if !ok {
					return 0, nil, io.EOF
				}
				return copy(b, pkt), nil, nil
			},
			MockConn: netconn.MockConn{
				ReadFunc: func(b []byte) (n int, err error) {
					pkt, ok := <-udpChan
					if !ok {
						return 0, io.EOF
					}
					return copy(b, pkt), nil
				},
				CloseFunc: func() error {
					return nil
				},
			},
		}

		pc := packet.NewConstructor()
		for {
			_, err = pc.ReadUDP(mockUDPConn)
			if err == io.EOF {
				return
			}

			assert.ErrorIs(t, err, nil, "no error when udp packet")
			assert.Equal(t, true, pc.ToPacket().Valid(), "packet is valid")
			assert.Equal(t, packet.PacketTypeData, pc.ToPacket().Type(), "packet is data")

			pkt := packet.DataPacket(pc.ToPacket())
			assert.Equal(t, net.ParseIP(*client.IP), pkt.IP(), "ip is the same as client")

			decrypted, err := serverAesKey.Decrypt(pkt.Data())
			assert.ErrorIs(t, err, nil, "no error when decrypting data")

			src, dest, proto := netutil.GetAddr(decrypted)
			assert.NotEqual(t, "", src, "src address is not empty")
			assert.NotEqual(t, "", dest, "dest address is not empty")
			assert.NotEqual(t, waterutil.ICMP, proto, "packet is udp")

			destAddr := waterutil.IPv4Destination(decrypted)
			srcAddr := waterutil.IPv4Source(decrypted)
			waterutil.SetIPv4Destination(decrypted, srcAddr)
			waterutil.SetIPv4Source(decrypted, destAddr)

			encrypted, err := testAesKey.Encrypt(pkt.Data())
			assert.ErrorIs(t, err, nil, "no error when encrypting data")

			pc.MakeDataPacket(encrypted, net.ParseIP(otherIP))

			client.HandlePacket(pc, nil, nil, true, false)
		}
	}()

	err = pinger.Run()
	assert.ErrorIs(t, err, nil, "no errors when sending pings")

	assert.Equal(t, float64(0), pinger.Statistics().PacketLoss, "No packets were dropped")

	client.Stop()
}
