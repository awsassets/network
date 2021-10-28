package signals

import (
	"context"
	"fmt"
	"sync"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/signal/types"
	"github.com/fasthttp/websocket"
)

var (
	ErrSignalEntryNotLoaded = fmt.Errorf("signal entry not loaded")
)

type SignalStore struct {
	mp     *sync.Map
	msgs   chan Message
	conns  chan string
	ctx    context.Context
	wg     *sync.WaitGroup
	config *configure.Config

	dialer websocket.Dialer
}

type Message struct {
	Msg  types.Message
	Node string
}

func New(ctx context.Context, config *configure.Config, wg *sync.WaitGroup, dialer websocket.Dialer) *SignalStore {
	return &SignalStore{
		mp:     &sync.Map{},
		msgs:   make(chan Message, 100),
		conns: make(chan string, 100),
		ctx:    ctx,
		dialer: dialer,
		wg:     wg,
		config: config,
	}
}

func (s *SignalStore) Messages() <-chan Message {
	return s.msgs
}

func (s *SignalStore) Conns() <-chan string {
	return s.conns
}

func (s *SignalStore) Register(server configure.SignalServer) {
	e, ok := s.mp.LoadOrStore(server.Name, &SignalEntry{
		Server: server,
	})
	entry := e.(*SignalEntry)
	if ok {
		if len(entry.Server.AccessPoints) != len(server.AccessPoints) {
			entry.Server.AccessPoints = server.AccessPoints
		} else {
			for i, a := range entry.Server.AccessPoints {
				if a != server.AccessPoints[i] {
					entry.Server.AccessPoints = server.AccessPoints
					break
				}
			}
		}
	} else {
		go entry.Start(s)
	}
}

func (s *SignalStore) Broadcast(msg types.Message) {
	s.mp.Range(func(key, value interface{}) bool {
		entry := value.(*SignalEntry)
		if err := <-entry.Ready; err != nil {
			return true
		}
		if !entry.stopped {
			_ = entry.Write(msg)
		}
		return true
	})
}

func (s *SignalStore) Write(name string, msg types.Message) error {
	e, ok := s.mp.Load(name)
	if !ok {
		return ErrSignalEntryNotLoaded
	}

	return e.(*SignalEntry).Write(msg)
}

func (s *SignalStore) Deregister(name string) {
	if e, ok := s.mp.LoadAndDelete(name); ok {
		entry := e.(*SignalEntry)
		entry.stopped = true
		entry.cancel()
	}
}
