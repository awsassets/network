package signal_store

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/types"
	"github.com/fasthttp/websocket"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var (
	ErrSignalEntryNotReady = fmt.Errorf("signal entry not ready")
	ErrSignalEntryStopped  = fmt.Errorf("signal entry stopped")
)

type entry struct {
	Server  configure.SignalServer
	ctx     context.Context
	cancel  context.CancelFunc
	conn    *websocket.Conn
	stopped bool
	mtx     sync.Mutex
	Ready   chan error
	tkn     string
}

func (e *entry) start(s *SignalStore) {
	s.wg.Add(1)
	defer s.wg.Done()
	// todo connect to signal servers and forward messages to the store
	for {
		if s.ctx.Err() != nil {
			return
		}

		e.mtx.Lock()
		e.Ready = make(chan error, 1)

		e.ctx, e.cancel = context.WithCancel(context.Background())

		e.conn = e.new(s.ctx, s.config, s.dialer)
		if e.conn == nil {
			e.Ready <- ErrSignalEntryStopped
			close(e.Ready)
			e.mtx.Unlock()
			return
		}
		if e.stopped {
			e.conn.Close()
			e.Ready <- ErrSignalEntryStopped
			close(e.Ready)
			e.mtx.Unlock()
			return
		}

		go e.read(s.msgs)

		close(e.Ready)
		e.mtx.Unlock()

		s.conns <- e.Server.Name

		select {
		case <-s.ctx.Done():
		case <-e.ctx.Done():
		}
		e.conn.Close()
	}
}

func (e *entry) read(msgs chan Message) {
	var (
		data []byte
		err  error
		msg  types.Message
	)
	defer e.cancel()
	for {
		_, data, err = e.conn.ReadMessage()
		if err != nil {
			return
		}

		if err = json.Unmarshal(data, &msg); err != nil {
			logrus.Warn("bad message from signal: ", err)
			continue
		}

		msgs <- Message{
			Msg:  msg,
			Node: e.Server.Name,
		}
	}
}

func (e *entry) Write(msg types.Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.conn == nil {
		return ErrSignalEntryNotReady
	}

	return e.conn.WriteMessage(websocket.TextMessage, data)
}

func (e *entry) new(ctx context.Context, config *configure.Config, dialer websocket.Dialer) *websocket.Conn {
	var (
		conn *websocket.Conn
		err  error
	)

	header := http.Header{}
	header.Add("mode", "signal")
	header.Add("authentication", e.tkn)
	nodePl, _ := json.MarshalToString(types.JoinPayloadSignal{
		Name:               config.Name,
		AdvertiseAddresses: config.AdvertiseAddresses,
		SignalServers:      config.SignalServers,
	})
	header.Add("signal", nodePl)

	for {
		for _, ip := range e.Server.AccessPoints {
			conn, _, err = dialer.Dial(fmt.Sprintf("wss://%s", ip), header)
			if err != nil {
				logrus.Errorf("failed to connect to signal server %s on %s: %e", e.Server.Name, ip, err)
			} else {
				logrus.Infof("connected to signal server %s on %s", e.Server.Name, ip)
				return conn
			}
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return nil
			}
		}
		select {
		case <-time.After(time.Second * 5):
		case <-ctx.Done():
			return nil
		}
	}
}
