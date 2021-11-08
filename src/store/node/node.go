package node_store

import (
	"time"

	"github.com/disembark/network/src/cache"
	dns_store "github.com/disembark/network/src/store/dns"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type Store interface {
	Stop()
	GetNode(name string) (Node, bool)
	SetNode(name string, node Node)
	Serialize() []cache.CacheItem
	Merge(items []cache.CacheItem)
}

type MockNodeStore struct {
	StopFunc      func()
	GetNodeFunc   func(name string) (Node, bool)
	SetNodeFunc   func(name string, node Node)
	SerializeFunc func() []cache.CacheItem
	MergeFunc     func(items []cache.CacheItem)
}

func (n MockNodeStore) Stop() {
	n.StopFunc()
}

func (n MockNodeStore) GetNode(name string) (Node, bool) {
	return n.GetNodeFunc(name)
}

func (n MockNodeStore) SetNode(name string, node Node) {
	n.SetNodeFunc(name, node)
}

func (n MockNodeStore) Serialize() []cache.CacheItem {
	return n.SerializeFunc()
}

func (n MockNodeStore) Merge(items []cache.CacheItem) {
	n.MergeFunc(items)
}

type NodeStore struct {
	cache cache.Cache
	dns   dns_store.Store
}

type Node struct {
	types.JoinPayloadNode
}

func New() Store {
	return &NodeStore{
		cache: cache.New(time.Minute, time.Minute*30),
	}
}

func NewWithDns(dns dns_store.Store) Store {
	return &NodeStore{
		cache: cache.New(time.Minute, time.Minute*30),
		dns:   dns,
	}
}

func (n *NodeStore) Stop() {
	n.cache.Stop()
}

func (n *NodeStore) GetNode(name string) (Node, bool) {
	obj, ok := n.cache.Get(name)
	if ok {
		return obj.(Node), true
	}

	return Node{}, false
}

func (n *NodeStore) SetNode(name string, node Node) {
	logrus.Debugf("new node: %s - %s", name, node.IP)
	if v, ok := n.cache.Get(name); ok {
		item := v.(Node)
		n.cache.Delete(item.IP)
		if n.dns != nil {
			for _, hostname := range item.DnsAliases {
				n.dns.DeleteRecord(hostname, item.IP)
			}
		}
	}
	n.cache.Store(name, node)
	n.cache.Store(node.IP, node)
	if n.dns != nil {
		for _, hostname := range node.DnsAliases {
			n.dns.StoreRecord(hostname, node.IP)
		}
	}
}

func (n *NodeStore) Serialize() []cache.CacheItem {
	return n.cache.ItemsArray()
}

func (n *NodeStore) Merge(items []cache.CacheItem) {
	for _, v := range items {
		if v.Expired() {
			continue
		}

		node := Node{}
		if err := json.Unmarshal(utils.OrPanic(json.Marshal(v.Object))[0].([]byte), &node); err != nil {
			logrus.Warn("bad node: ", err)
			continue
		}

		v.Object = node

		old, merged := n.cache.Merge(v)
		if n.dns != nil {
			if merged {
				oldNode := old.(Node)
				for _, hostname := range oldNode.DnsAliases {
					n.dns.DeleteRecord(hostname, oldNode.IP)
				}
			}

			for _, hostname := range node.DnsAliases {
				n.dns.StoreRecord(hostname, node.IP)
			}
		}
	}
}
