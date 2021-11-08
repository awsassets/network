package conn_store

import (
	"context"
	"sync"
	"time"

	aes_store "github.com/disembark/network/src/store/aes"
	node_store "github.com/disembark/network/src/store/node"
	"github.com/sirupsen/logrus"
)

type Store interface {
	Stop(ip string)
	Get(ip string) Conn
	New(ip string) Conn
}

type ConnStore struct {
	mp    *sync.Map
	nodes node_store.Store
	aes   aes_store.Store
	ourIP *string
}

type MockConnStore struct {
	StopFunc func(ip string)
	GetFunc  func(ip string) Conn
	NewFunc  func(ip string) Conn
}

func (c MockConnStore) Stop(ip string) {
	c.StopFunc(ip)
}

func (c MockConnStore) Get(ip string) Conn {
	return c.GetFunc(ip)
}

func (c MockConnStore) New(ip string) Conn {
	return c.NewFunc(ip)
}

func New(nodes node_store.Store, ourIP *string) Store {
	s := &ConnStore{
		mp: &sync.Map{},

		nodes: nodes,
		aes:   aes_store.New(),
		ourIP: ourIP,
	}

	go s.runner()

	return s
}

func (c *ConnStore) Stop(ip string) {
	if v, ok := c.mp.LoadAndDelete(ip); ok {
		conn := v.(Conn)

		logrus.Debugf("cleaning up connection: %s - %s", conn.Name(), conn.IP())

		conn.Stop()
	}
}

func (c *ConnStore) Get(ip string) Conn {
	if v, ok := c.mp.Load(ip); ok {
		return v.(Conn)
	}

	return nil
}

func (c *ConnStore) New(ip string) Conn {
	node, ok := c.nodes.GetNode(ip)
	if !ok {
		return nil
	}

	conn := &ConnInstance{
		ip:       node.IP,
		name:     node.Name,
		nodes:    c.nodes,
		aes:      c.aes,
		ourIP:    c.ourIP,
		lastUsed: time.Now(),
	}

	if v, ok := c.mp.LoadOrStore(node.IP, conn); ok {
		return v.(Conn)
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn.ctx = ctx
	conn.cancel = cancel

	c.aes.GetOrNew(node.Name)

	go func() {
		conn.manageUDP()
		c.Stop(conn.ip)
	}()

	go func() {
		conn.manageTCP()
		c.Stop(conn.ip)
	}()

	return conn
}

func (c *ConnStore) runner() {
	tick := time.NewTicker(time.Minute * 5)
	for range tick.C {
		c.cleanup()
	}
}

func (c *ConnStore) cleanup() {
	c.mp.Range(func(key, value interface{}) bool {
		conn := value.(Conn)

		if conn.LastUsed().Before(time.Now().Add(-time.Minute * 10)) {
			c.Stop(conn.IP())
		}

		return true
	})
}
