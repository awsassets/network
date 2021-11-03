package event_store

import (
	"sync"
	"time"

	"github.com/disembark/network/src/cache"
)

type Store struct {
	cache *cache.Cache
	mtx   *sync.Mutex
}

func New() *Store {
	return &Store{
		cache: cache.New(time.Hour, time.Hour*12),
		mtx:   &sync.Mutex{},
	}
}

func (e *Store) Register(name string) bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if _, ok := e.cache.Get(name); ok {
		return true
	}

	e.cache.Store(name, true)
	return false
}
