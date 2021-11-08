package node

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/packet"
	"github.com/disembark/network/src/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_Node(t *testing.T) {
	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Bind:                   "127.0.0.1:0",
	}

	config.MockConfig()

	pub, priv, err := helpers.GenerateClientTls(config)
	assert.ErrorIs(t, err, nil, "Generate a client cert and priv key")
	config.ClientPublicKey = utils.B2S(pub)
	config.ClientPrivateKey = utils.B2S(priv)

	node := newNode(config)
	defer node.Stop()

	time.Sleep(time.Second)

	tcpAddr := node.tcpConns[0].Addr().String()
	udpAddr := node.udpConns[0].LocalAddr().String()

	pc := packet.NewConstructor()

	tcpconn, err := net.Dial("tcp", tcpAddr)
	assert.ErrorIs(t, err, nil, "we dial the tcp connection")
	udpconn, err := net.Dial("udp", udpAddr)
	assert.ErrorIs(t, err, nil, "we dial the udp connection")

	id, _ := uuid.NewRandom()

	pc.MakePingPacket(id, net.ParseIP("10.10.0.1"))
	_, err = tcpconn.Write(pc.ToTCP())
	assert.ErrorIs(t, err, nil, "we write a tcp packet")

	_, err = udpconn.Write(pc.ToUDP())
	assert.ErrorIs(t, err, nil, "we write a udp packet")

	node.Stop()
}
