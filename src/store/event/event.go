package event_store

import (
	"sync"
	"time"

	"github.com/disembark/network/src/cache"
)

type EventStore struct {
	cache cache.Cache
	mtx   *sync.Mutex
}

type MockEventStore struct {
	StopFunc     func()
	RegisterFunc func(name string) bool
}

func (e MockEventStore) Stop() {
	e.StopFunc()
}

func (e MockEventStore) Register(name string) bool {
	return e.RegisterFunc(name)
}

type Store interface {
	Stop()
	Register(name string) bool
}

func New() Store {
	return &EventStore{
		cache: cache.New(time.Hour, time.Hour*12),
		mtx:   &sync.Mutex{},
	}
}

func (e *EventStore) Stop() {
	e.cache.Stop()
}

func (e *EventStore) Register(name string) bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if _, ok := e.cache.Get(name); ok {
		return true
	}

	e.cache.Store(name, true)
	return false
}
