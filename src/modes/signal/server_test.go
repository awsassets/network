package signal

import (
	"context"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	signal_store "github.com/disembark/network/src/store/signal"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/fasthttp/websocket"
	"github.com/stretchr/testify/assert"
)

func Test_ServerNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Mode:                   configure.ModeSignal,
		Bind:                   "127.1.201.132:8888",
		SignalServers:          []configure.SignalServer{},
	}

	server := newServer(ctx, config)

	outMsgCh := make(chan types.Message, 100)
	inMsgCh := make(chan signal_store.Message, 100)
	server.signal = signal_store.MockSignalStore{
		MessagesFunc: func() <-chan signal_store.Message {
			return inMsgCh
		},
		BroadcastFunc: func(msg types.Message) {
			outMsgCh <- msg
		},
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  utils.TlsConfig(config.SignalServerPublicKey),
	}

	jt, err := helpers.GenerateClientJoinToken(config, configure.ModeNode, "test")
	assert.ErrorIs(t, err, nil, "no error when generating token")

	header := http.Header{}
	header.Set("mode", string(configure.ModeNode))
	header.Set("authentication", jt)
	header.Set("node", utils.OrPanic(json.MarshalToString(types.JoinPayloadNode{
		Name: "test",
		IP:   "dynamic",
	}))[0].(string))

	time.Sleep(time.Second)

	conn, _, err := dialer.Dial("wss://127.1.201.132:8888", header)
	assert.ErrorIs(t, err, nil, "no error when generating token")
	assert.NotNil(t, conn, nil, "connection is not nil")

	<-outMsgCh

	var ourIP string
	{
		_, data, err := conn.ReadMessage()
		assert.ErrorIs(t, err, nil, "read is successful")

		var msg types.Message
		err = json.Unmarshal(data, &msg)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		assert.Equal(t, types.MessageTypeNodeState, msg.Type, "The message is a node state")
		pl := types.MessageNodeState{}
		err = json.Unmarshal(msg.Payload, &pl)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		ourIP = pl.Current.IP
	}

	{
		msg := types.Message{Type: types.MessageTypePing}

		err = conn.WriteMessage(websocket.TextMessage, utils.OrPanic(json.Marshal(msg))[0].([]byte))
		assert.ErrorIs(t, err, nil, "write is successful")

		<-outMsgCh
	}

	_ = conn.Close()

	conn, _, err = dialer.Dial("wss://127.1.201.132:8888", header)
	assert.ErrorIs(t, err, nil, "no error when generating token")
	assert.NotNil(t, conn, nil, "connection is not nil")

	<-outMsgCh

	{
		_, data, err := conn.ReadMessage()
		assert.ErrorIs(t, err, nil, "read is successful")

		var msg types.Message
		err = json.Unmarshal(data, &msg)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		assert.Equal(t, types.MessageTypeNodeState, msg.Type, "The message is a node state")
		pl := types.MessageNodeState{}
		err = json.Unmarshal(msg.Payload, &pl)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		assert.Equal(t, ourIP, pl.Current.IP, "The signal server gives us the old ip")
	}

	_ = conn.Close()

	header.Set("node", utils.OrPanic(json.MarshalToString(types.JoinPayloadNode{
		Name: "test",
		IP:   "10.10.0.1",
	}))[0].(string))

	conn, _, err = dialer.Dial("wss://127.1.201.132:8888", header)
	assert.ErrorIs(t, err, nil, "no error when generating token")
	assert.NotNil(t, conn, nil, "connection is not nil")

	<-outMsgCh

	{
		_, data, err := conn.ReadMessage()
		assert.ErrorIs(t, err, nil, "read is successful")

		var msg types.Message
		err = json.Unmarshal(data, &msg)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		assert.Equal(t, types.MessageTypeNodeState, msg.Type, "The message is a node state")
		pl := types.MessageNodeState{}
		err = json.Unmarshal(msg.Payload, &pl)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		assert.Equal(t, "10.10.0.1", pl.Current.IP, "The signal server gives us the old ip")
	}
}

func Test_ServerRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Mode:                   configure.ModeRelayServer,
		Bind:                   "127.1.201.132:8889",
		SignalServers:          []configure.SignalServer{},
	}

	server := newServer(ctx, config)

	outMsgCh := make(chan types.Message, 100)
	inMsgCh := make(chan signal_store.Message, 100)
	server.signal = signal_store.MockSignalStore{
		MessagesFunc: func() <-chan signal_store.Message {
			return inMsgCh
		},
		BroadcastFunc: func(msg types.Message) {
			outMsgCh <- msg
		},
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  utils.TlsConfig(config.SignalServerPublicKey),
	}

	jt, err := helpers.GenerateClientJoinToken(config, configure.ModeRelayServer, "test")
	assert.ErrorIs(t, err, nil, "no error when generating token")

	header := http.Header{}
	header.Set("mode", string(configure.ModeRelayServer))
	header.Set("authentication", jt)
	header.Set("name", "test")

	time.Sleep(time.Second)

	conn, _, err := dialer.Dial("wss://127.1.201.132:8889", header)
	assert.ErrorIs(t, err, nil, "no error when generating token")
	assert.NotNil(t, conn, nil, "connection is not nil")

	{
		_, data, err := conn.ReadMessage()
		assert.ErrorIs(t, err, nil, "read is successful")

		var msg types.Message
		err = json.Unmarshal(data, &msg)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		assert.Equal(t, types.MessageTypeNodeState, msg.Type, "The message is a node state")
		pl := types.MessageNodeState{}
		err = json.Unmarshal(msg.Payload, &pl)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
	}

	{
		msg := types.Message{Type: types.MessageTypePing}

		err = conn.WriteMessage(websocket.TextMessage, utils.OrPanic(json.Marshal(msg))[0].([]byte))
		assert.ErrorIs(t, err, nil, "write is successful")
	}
}

func Test_ServerSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &configure.Config{
		SignalServerPublicKey:  "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----",
		SignalServerPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqiu86E8ihlXZeNLP\nfth0TKIsEwn3/VZH/yAVdYTFidChRANCAAT8IG2tuuHfO0va/ZzgQPz7tLpvPboG\nlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KGdTR2GXXB\n-----END PRIVATE KEY-----",
		TokenKey:               hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
		Name:                   "test",
		Mode:                   configure.ModeSignal,
		Bind:                   "127.1.201.132:8887",
		SignalServers:          []configure.SignalServer{},
	}

	server := newServer(ctx, config)

	outMsgCh := make(chan types.Message, 100)
	inMsgCh := make(chan signal_store.Message, 100)
	server.signal = signal_store.MockSignalStore{
		MessagesFunc: func() <-chan signal_store.Message {
			return inMsgCh
		},
		BroadcastFunc: func(msg types.Message) {
			outMsgCh <- msg
		},
		RegisterFunc: func(server configure.SignalServer, tkn string) {

		},
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  utils.TlsConfig(config.SignalServerPublicKey),
	}

	jt, err := helpers.GenerateClientJoinToken(config, configure.ModeSignal, "test")
	assert.ErrorIs(t, err, nil, "no error when generating token")

	header := http.Header{}
	header.Set("mode", string(configure.ModeSignal))
	header.Set("authentication", jt)
	header.Set("signal", utils.OrPanic(json.MarshalToString(types.JoinPayloadSignal{
		Name: "test",
	}))[0].(string))

	time.Sleep(time.Second)

	conn, _, err := dialer.Dial("wss://127.1.201.132:8887", header)
	assert.ErrorIs(t, err, nil, "no error when generating token")
	assert.NotNil(t, conn, nil, "connection is not nil")

	{
		_, data, err := conn.ReadMessage()
		assert.ErrorIs(t, err, nil, "read is successful")

		var msg types.Message
		err = json.Unmarshal(data, &msg)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
		assert.Equal(t, types.MessageTypeSignalState, msg.Type, "The message is a node state")
		pl := types.MessageSignalState{}
		err = json.Unmarshal(msg.Payload, &pl)
		assert.ErrorIs(t, err, nil, "unmarshal is successful")
	}

	{
		msg := types.Message{Type: types.MessageTypePing}

		err = conn.WriteMessage(websocket.TextMessage, utils.OrPanic(json.Marshal(msg))[0].([]byte))
		assert.ErrorIs(t, err, nil, "write is successful")
	}

	{
		msg := types.Message{Type: types.MessageTypeNodeRegister, Payload: utils.OrPanic(json.Marshal(types.MessageNodeRegister{
			Node: types.JoinPayloadNode{
				Name: "based",
				IP:   "10.10.212.12",
			},
			DynamicIP: true,
		}))[0].([]byte)}

		err = conn.WriteMessage(websocket.TextMessage, utils.OrPanic(json.Marshal(msg))[0].([]byte))
		assert.ErrorIs(t, err, nil, "write is successful")
	}

	{
		msg := types.Message{Type: types.MessageTypeSignalRegister, Payload: utils.OrPanic(json.Marshal(types.MessageSignalRegister{
			Signal: types.MessageSignalState{
				SignalServer: configure.SignalServer{
					Name: "xqcL",
				},
				Nodes: server.node.Serialize(),
				DHCP:  server.dhcp.Serialize(),
			},
		}))[0].([]byte), Key: "based"}

		err = conn.WriteMessage(websocket.TextMessage, utils.OrPanic(json.Marshal(msg))[0].([]byte))
		assert.ErrorIs(t, err, nil, "write is successful")
	}
}
