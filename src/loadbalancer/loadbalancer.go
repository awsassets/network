package loadbalancer

import "sync/atomic"

type LoadBalancer struct {
	idx   *uint64
	items []interface{}
}

func NewLoadBalancer(items ...interface{}) *LoadBalancer {
	zero := uint64(0)
	return &LoadBalancer{
		idx:   &zero,
		items: items,
	}
}

func (l *LoadBalancer) GetNext() interface{} {
	return l.items[atomic.AddUint64(l.idx, 1)%uint64(len(l.items))]
}

func (l *LoadBalancer) GetItem(idx int) interface{} {
	return l.items[idx%len(l.items)]
}

func (l *LoadBalancer) GetItems() []interface{} {
	return l.items
}

func (l *LoadBalancer) AddItem(item interface{}) {
	l.items = append(l.items, item)
}
