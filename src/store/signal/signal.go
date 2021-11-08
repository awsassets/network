package signal_store

import (
	"context"
	"fmt"
	"sync"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/types"
	"github.com/fasthttp/websocket"
)

var (
	ErrSignalEntryNotLoaded = fmt.Errorf("signal entry not loaded")
)

type Store interface {
	Messages() <-chan Message
	Conns() <-chan string
	Register(server configure.SignalServer, tkn string)
	Broadcast(msg types.Message)
	Write(name string, msg types.Message) error
	Deregister(name string)
}

type MockSignalStore struct {
	MessagesFunc   func() <-chan Message
	ConnsFunc      func() <-chan string
	RegisterFunc   func(server configure.SignalServer, tkn string)
	BroadcastFunc  func(msg types.Message)
	WriteFunc      func(name string, msg types.Message) error
	DeregisterFunc func(name string)
}

type SignalStore struct {
	mp     *sync.Map
	msgs   chan Message
	conns  chan string
	ctx    context.Context
	wg     *sync.WaitGroup
	config *configure.Config

	dialer websocket.Dialer
}

func (s MockSignalStore) Messages() <-chan Message {
	return s.MessagesFunc()
}

func (s MockSignalStore) Conns() <-chan string {
	return s.ConnsFunc()
}

func (s MockSignalStore) Register(server configure.SignalServer, tkn string) {
	s.RegisterFunc(server, tkn)
}

func (s MockSignalStore) Broadcast(msg types.Message) {
	s.BroadcastFunc(msg)
}

func (s MockSignalStore) Write(name string, msg types.Message) error {
	return s.WriteFunc(name, msg)
}

func (s MockSignalStore) Deregister(name string) {
	s.DeregisterFunc(name)
}

type Message struct {
	Msg  types.Message
	Node string
}

func New(ctx context.Context, config *configure.Config, wg *sync.WaitGroup, dialer websocket.Dialer) Store {
	return &SignalStore{
		mp:     &sync.Map{},
		msgs:   make(chan Message, 100),
		conns:  make(chan string, 100),
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

func (s *SignalStore) Register(server configure.SignalServer, tkn string) {
	e, ok := s.mp.LoadOrStore(server.Name, &entry{
		Server: server,
		tkn:    tkn,
	})
	entry := e.(*entry)
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
		go entry.start(s)
	}
}

func (s *SignalStore) Broadcast(msg types.Message) {
	s.mp.Range(func(key, value interface{}) bool {
		entry := value.(*entry)
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

	return e.(*entry).Write(msg)
}

func (s *SignalStore) Deregister(name string) {
	if e, ok := s.mp.LoadAndDelete(name); ok {
		entry := e.(*entry)
		entry.stopped = true
		entry.cancel()
	}
}
