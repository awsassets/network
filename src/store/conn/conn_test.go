package conn_store

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/netconn"
	"github.com/disembark/network/src/packet"
	aes_store "github.com/disembark/network/src/store/aes"
	event_store "github.com/disembark/network/src/store/event"
	node_store "github.com/disembark/network/src/store/node"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_Conn(t *testing.T) {
	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	logrus.SetLevel(logrus.TraceLevel)

	done := false
	node := node_store.New()
	ip := utils.StringPointer("10.10.0.1")

	rIp := "10.10.0.2"

	events := event_store.New()
	aes := aes_store.New()

	config := &configure.Config{
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----\n",
	}

	pubBytes, privBytes, err := helpers.GenerateClientTls(config)
	assert.ErrorIs(t, err, nil, "No error when creating a key")

	b, _ := pem.Decode(privBytes)

	cert, _ := x509.ParsePKCS8PrivateKey(b.Bytes)
	priv := ecies.ImportECDSA(cert.(*ecdsa.PrivateKey))

	dataCh := make(chan []byte, 100)

	processPkt := func(pc *packet.PacketConstructor) bool {
		assert.Equal(t, true, pc.ToPacket().Valid(), "a valid packet is generated")
		pkt := pc.ToPacket()

		switch pkt.Type() {
		case packet.PacketTypePing:
			pkt := packet.PingPacket(pkt)
			if events.Register(pkt.ID().String()) {
				return false
			}
			assert.Equal(t, *ip, pkt.IP().String(), "our ip is sent with the packet")

			n, ok := node.GetNode(pkt.IP().String())
			assert.Equal(t, true, ok, "the node is in the store")

			key := aes.Get(n.Name)
			if key == nil {
				pc.MakePongPacket(pkt.ID())
			} else {
				data := make([]byte, 32)
				_, _ = rand.Read(data)
				h := hmac.New(sha3.New512, key.KeyRaw())
				_, _ = h.Write(data)

				pc.MakePongAesPacket(pkt.ID(), data, h.Sum(nil))
			}

			return true
		case packet.PacketTypeExchange:
			pkt := packet.ExchangePacket(pkt)
			aesKey, err := priv.Decrypt(pkt.Data(), nil, nil)
			assert.ErrorIs(t, err, nil, "No error when decrypting data")

			assert.Equal(t, 32, len(aesKey), "AES Key is 32 bytes")

			n, ok := node.GetNode(pkt.IP().String())
			assert.Equal(t, true, ok, "the node is in the store")

			aes.Store(n.Name, aesKey)
		case packet.PacketTypeData:
			pkt := packet.DataPacket(pkt)
			n, ok := node.GetNode(pkt.IP().String())
			assert.Equal(t, true, ok, "the node exists")
			key := aes.Get(n.Name)
			assert.NotNil(t, key, "the key exists")
			data, err := key.Decrypt(pkt.Data())
			assert.ErrorIs(t, err, nil, "No error when decrypting data")
			dataCh <- data
		}

		return false
	}

	tcp, err := net.Listen("tcp", "127.0.0.5:0")
	assert.ErrorIs(t, err, nil, "No error when making a listener")
	defer tcp.Close()
	go func() {
		pc := packet.NewConstructor()
		for {
			tcpConn, err := tcp.Accept()
			if done {
				return
			}

			assert.ErrorIs(t, err, nil, "No error when accepting a connection")
			defer tcpConn.Close()

			go func() {
				for {
					err = pc.ReadTCP(tcpConn)
					if done {
						return
					}

					assert.ErrorIs(t, err, nil, "No error when reading a connection")
					if processPkt(pc) {
						_, err = tcpConn.Write(pc.ToTCP())
						assert.ErrorIs(t, err, nil, "No error when writing a packet")
					}
				}
			}()
		}
	}()

	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	assert.ErrorIs(t, err, nil, "No error when making a listener")
	defer udp.Close()
	go func() {
		pc := packet.NewConstructor()
		for {
			addr, err := pc.ReadUDP(udp.(netconn.UDPConn))
			if done {
				return
			}
			assert.ErrorIs(t, err, nil, "No error when reading a connection")
			if processPkt(pc) {
				_, err = udp.WriteTo(pc.ToUDP(), addr)
				assert.ErrorIs(t, err, nil, "No error when writing a packet")
			}

		}
	}()

	node.SetNode("test", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "test",
			IP:   rIp,
			AdvertiseAddresses: []string{
				tcp.Addr().String(),
			},
			PublicKey: utils.B2S(pubBytes),
		},
	})

	node.SetNode("main", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "main",
			IP:   *ip,
		},
	})

	conn := New(node, ip).(*ConnStore)

	c := conn.New(rIp).(*ConnInstance)
	defer conn.Stop(rIp)

	assert.NotNil(t, c, "We get a valid connection back")
	assert.NotNil(t, c.Aes(), "We have an aes key for this connection")

	assert.Equal(t, c, conn.Get(rIp), "we get the old connection back")
	assert.Equal(t, c, conn.New(rIp), "we get the old connection back")

	pc := packet.NewConstructor()

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		err = c.WriteTCP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "No error when reading message")
		data := <-dataCh
		assert.Equal(t, hash(cpy), hash(data), "the data is the same")
	}

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		err = c.WriteUDP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "No error when reading message")
		data := <-dataCh
		assert.Equal(t, hash(cpy), hash(data), "the data is the same")
	}

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		c.forceUDP = true
		c.forceTCP = false

		err = c.WriteTCP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "No error when reading message")
		data := <-dataCh
		assert.Equal(t, hash(cpy), hash(data), "the data is the same")
	}

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		c.forceUDP = true
		c.forceTCP = false

		err = c.WriteTCP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "No error when reading message")
		data := <-dataCh
		assert.Equal(t, hash(cpy), hash(data), "the data is the same")
	}

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		c.forceUDP = false
		c.forceTCP = true

		err = c.WriteUDP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "No error when reading message")
		data := <-dataCh
		assert.Equal(t, hash(cpy), hash(data), "the data is the same")
	}

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		c.forceUDP = false
		c.forceTCP = true

		err = c.WriteUDP(pc.ToTCP())
		assert.ErrorIs(t, err, nil, "No error when reading message")
		data := <-dataCh
		assert.Equal(t, hash(cpy), hash(data), "the data is the same")
	}

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		c.forceUDP = true
		c.forceTCP = true

		err = c.WriteUDP(pc.ToTCP())
		assert.ErrorIs(t, err, ErrNoRoute, "Err when writing message")
	}

	{
		message := make([]byte, packet.MTU+aes_store.BlockSize)
		_, _ = rand.Read(message[aes_store.BlockSize:])

		cpy := make([]byte, packet.MTU)
		copy(cpy, message[aes_store.BlockSize:])

		message, err = c.Aes().Encrypt(message)
		assert.ErrorIs(t, err, nil, "No error when encrypting message")

		pc.MakeDataPacket(message, net.ParseIP(*ip))

		time.Sleep(time.Second)

		c.forceUDP = true
		c.forceTCP = true

		err = c.WriteTCP(pc.ToTCP())
		assert.ErrorIs(t, err, ErrNoRoute, "Err when writing message")
	}

	time.Sleep(time.Second)

	conn.cleanup()

	done = true
}

func Test_Conn2(t *testing.T) {
	runtime.GOMAXPROCS(1)

	logrus.SetLevel(logrus.TraceLevel)

	done := false
	node := node_store.New()
	ip := utils.StringPointer("10.10.0.1")

	rIp := "10.10.0.2"

	events := event_store.New()
	aes := aes_store.New()

	config := &configure.Config{
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----\n",
	}

	pubBytes, privBytes, err := helpers.GenerateClientTls(config)
	assert.ErrorIs(t, err, nil, "No error when creating a key")

	b, _ := pem.Decode(privBytes)

	cert, _ := x509.ParsePKCS8PrivateKey(b.Bytes)
	priv := ecies.ImportECDSA(cert.(*ecdsa.PrivateKey))

	dataCh := make(chan []byte, 100)

	processPkt := func(pc *packet.PacketConstructor) bool {
		assert.Equal(t, true, pc.ToPacket().Valid(), "a valid packet is generated")
		pkt := pc.ToPacket()

		switch pkt.Type() {
		case packet.PacketTypePing:
			pkt := packet.PingPacket(pkt)
			if events.Register(pkt.ID().String()) {
				return false
			}
			assert.Equal(t, *ip, pkt.IP().String(), "our ip is sent with the packet")

			n, ok := node.GetNode(pkt.IP().String())
			assert.Equal(t, true, ok, "the node is in the store")

			key := aes.Get(n.Name)
			if key == nil {
				pc.MakePongPacket(pkt.ID())
			} else {
				data := make([]byte, 32)
				_, _ = rand.Read(data)
				h := hmac.New(sha3.New512, key.KeyRaw())
				_, _ = h.Write(data)

				pc.MakePongAesPacket(pkt.ID(), data, h.Sum(nil))
			}

			return true
		case packet.PacketTypeExchange:
			pkt := packet.ExchangePacket(pkt)
			aesKey, err := priv.Decrypt(pkt.Data(), nil, nil)
			assert.ErrorIs(t, err, nil, "No error when decrypting data")

			assert.Equal(t, 32, len(aesKey), "AES Key is 32 bytes")

			n, ok := node.GetNode(pkt.IP().String())
			assert.Equal(t, true, ok, "the node is in the store")

			aes.Store(n.Name, aesKey)
		case packet.PacketTypeData:
			pkt := packet.DataPacket(pkt)
			n, ok := node.GetNode(pkt.IP().String())
			assert.Equal(t, true, ok, "the node exists")
			key := aes.Get(n.Name)
			assert.NotNil(t, key, "the key exists")
			data, err := key.Decrypt(pkt.Data())
			assert.ErrorIs(t, err, nil, "No error when decrypting data")
			dataCh <- data
		}

		return false
	}

	tcp, err := net.Listen("tcp", "127.0.0.5:0")
	assert.ErrorIs(t, err, nil, "No error when making a listener")
	defer tcp.Close()
	var tcpConn net.Conn
	closed := false
	go func() {
		pc := packet.NewConstructor()
		var err error
	start:
		tcpConn, err = tcp.Accept()
		if done {
			return
		}
		assert.ErrorIs(t, err, nil, "No error when accepting a connection")
		defer tcpConn.Close()

		for {
			err = pc.ReadTCP(tcpConn)
			if done {
				return
			}
			if closed {
				closed = false
				goto start
			}

			assert.ErrorIs(t, err, nil, "No error when reading a connection")
			if processPkt(pc) {
				_, err = tcpConn.Write(pc.ToTCP())
				assert.ErrorIs(t, err, nil, "No error when writing a packet")
			}
		}
	}()

	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	assert.ErrorIs(t, err, nil, "No error when making a listener")
	defer udp.Close()
	go func() {
		pc := packet.NewConstructor()
		for {
			addr, err := pc.ReadUDP(udp.(netconn.UDPConn))
			if done {
				return
			}
			assert.ErrorIs(t, err, nil, "No error when reading a connection")
			if processPkt(pc) {
				_, err = udp.WriteTo(pc.ToUDP(), addr)
				assert.ErrorIs(t, err, nil, "No error when writing a packet")
			}

		}
	}()

	node.SetNode("test", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "test",
			IP:   rIp,
			AdvertiseAddresses: []string{
				tcp.Addr().String(),
			},
			PublicKey: utils.B2S(pubBytes),
		},
	})

	node.SetNode("main", node_store.Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "main",
			IP:   *ip,
		},
	})

	conn := New(node, ip).(*ConnStore)

	c := conn.New(rIp)
	defer conn.Stop(rIp)

	assert.NotNil(t, c, "We get a valid connection back")
	assert.NotNil(t, c.Aes(), "We have an aes key for this connection")

	assert.Equal(t, c, conn.Get(rIp), "we get the old connection back")
	assert.Equal(t, c, conn.New(rIp), "we get the old connection back")

	time.Sleep(time.Second)

	closed = true
	tcpConn.Close()

	time.Sleep(time.Second * 5)

	conn.cleanup()

	done = true
}
