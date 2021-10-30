package node

import (
	"time"

	"github.com/disembark/network/src/cache"
	"github.com/disembark/network/src/modes/node/dns"
	"github.com/disembark/network/src/modes/signal/types"
	"github.com/disembark/network/src/utils"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type NodeStore struct {
	cache *cache.Cache
	dns   *dns.DNS
}

type Node struct {
	types.JoinPayloadNode
}

func New() *NodeStore {
	return &NodeStore{
		cache: cache.New(time.Minute, time.Minute*30),
	}
}

func NewWithDns(dns *dns.DNS) *NodeStore {
	return &NodeStore{
		cache: cache.New(time.Minute, time.Minute*30),
		dns:   dns,
	}
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
