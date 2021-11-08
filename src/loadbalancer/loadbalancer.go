package loadbalancer

import (
	"sync"
)

type LoadBalancer interface {
	GetNext() interface{}
	GetItem(idx int) interface{}
	GetItems() []interface{}
	AddItem(item interface{})
}

type loadBalancer struct {
	mtx   sync.Mutex
	idx   uint64
	items []interface{}
}

func New(items ...interface{}) LoadBalancer {
	return &loadBalancer{
		items: items,
	}
}

func (l *loadBalancer) GetNext() interface{} {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if len(l.items) == 0 {
		return nil
	}
	o := l.idx

	l.idx = (l.idx + 1) % uint64(len(l.items))

	return l.items[o]
}

func (l *loadBalancer) GetItem(idx int) interface{} {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if len(l.items) == 0 {
		return nil
	}

	return l.items[idx%len(l.items)]
}

func (l *loadBalancer) GetItems() []interface{} {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return l.items
}

func (l *loadBalancer) AddItem(item interface{}) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	l.items = append(l.items, item)
}
