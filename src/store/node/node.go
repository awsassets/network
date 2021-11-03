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

type Store struct {
	cache *cache.Cache
	dns   *dns_store.Store
}

type Node struct {
	types.JoinPayloadNode
}

func New() *Store {
	return &Store{
		cache: cache.New(time.Minute, time.Minute*30),
	}
}

func NewWithDns(dns *dns_store.Store) *Store {
	return &Store{
		cache: cache.New(time.Minute, time.Minute*30),
		dns:   dns,
	}
}

func (n *Store) GetNode(name string) (Node, bool) {
	obj, ok := n.cache.Get(name)
	if ok {
		return obj.(Node), true
	}

	return Node{}, false
}

func (n *Store) SetNode(name string, node Node) {
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

func (n *Store) Serialize() []cache.CacheItem {
	return n.cache.ItemsArray()
}

func (n *Store) Merge(items []cache.CacheItem) {
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
