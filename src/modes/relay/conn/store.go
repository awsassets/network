package conn_store

import (
	"context"
	"sync"
	"time"

	"github.com/disembark/network/src/loadbalancer"
	node_store "github.com/disembark/network/src/store/node"
	"github.com/sirupsen/logrus"
)

type Store interface {
	Stop(ip string)
	Get(ip string) Conn
	New(ip string) Conn
}

type StoreInstance struct {
	mp        *sync.Map
	nodes     node_store.Store
	udpConnLb loadbalancer.LoadBalancer
}

func New(nodes node_store.Store, lb loadbalancer.LoadBalancer) Store {
	s := &StoreInstance{
		mp:        &sync.Map{},
		nodes:     nodes,
		udpConnLb: lb,
	}

	go s.runner()

	return s
}

func (s *StoreInstance) Stop(ip string) {
	if v, ok := s.mp.LoadAndDelete(ip); ok {
		conn := v.(*ConnInstance)
		conn.deleted = true

		logrus.Debugf("cleaning up connection: %s - %s", conn.name, conn.ip)

		conn.cancel()
	}
}

func (s *StoreInstance) Get(ip string) Conn {
	if v, ok := s.mp.Load(ip); ok {
		return v.(*ConnInstance)
	}

	return nil
}

func (s *StoreInstance) New(ip string) Conn {
	node, ok := s.nodes.GetNode(ip)
	if !ok {
		return nil
	}

	if !node.Relay {
		return nil
	}

	c := &ConnInstance{
		ip:        node.IP,
		name:      node.Name,
		lastPing:  time.Now(),
		udpConnLb: s.udpConnLb,
	}

	if v, ok := s.mp.LoadOrStore(node.IP, c); ok {
		return v.(*ConnInstance)
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.ctx = ctx
	c.cancel = cancel

	return c
}

func (s *StoreInstance) runner() {
	tick := time.NewTicker(time.Minute * 5)
	for range tick.C {
		s.cleanup()
	}
}

func (s *StoreInstance) cleanup() {
	s.mp.Range(func(key, value interface{}) bool {
		conn := value.(*ConnInstance)

		if conn.lastPing.Before(time.Now().Add(-time.Minute * 10)) {
			s.Stop(conn.ip)
		}

		return true
	})
}
