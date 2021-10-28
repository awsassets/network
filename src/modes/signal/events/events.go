package events

import (
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

type Events struct {
	cache *cache.Cache
	mtx   *sync.Mutex
}

func New() *Events {
	return &Events{
		cache: cache.New(time.Hour*12, time.Hour),
		mtx:   &sync.Mutex{},
	}
}

func (e *Events) Register(name string) bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if _, ok := e.cache.Get(name); ok {
		return true
	}

	e.cache.SetDefault(name, true)
	return false
}
