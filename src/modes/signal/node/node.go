package node

import (
	"time"

	"github.com/disembark/network/src/modes/signal/types"
	"github.com/disembark/network/src/utils"
	jsoniter "github.com/json-iterator/go"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type NodeStore struct {
	cache *cache.Cache
}

type Node struct {
	types.JoinPayloadNode
}

func New() *NodeStore {
	return &NodeStore{
		cache: cache.New(time.Minute*30, time.Minute),
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
	if v, ok := n.cache.Get(name); ok {
		n.cache.Delete(v.(Node).IP)
	}
	n.cache.SetDefault(name, node)
	n.cache.SetDefault(node.IP, node)
}

func (d *NodeStore) Serialize() map[string]cache.Item {
	return d.cache.Items()
}

func (d *NodeStore) Merge(items map[string]cache.Item) {
	for k, v := range items {
		if v.Expired() {
			continue
		}
		if _, t, ok := d.cache.GetWithExpiration(k); ok && t.After(time.Unix(0, v.Expiration)) {
			continue
		}
		n := Node{}
		if err := json.Unmarshal(utils.OrPanic(json.Marshal(v.Object))[0].([]byte), &n); err != nil {
			logrus.Warn("bad node: ", err)
			continue
		}

		d.cache.Set(k, n, time.Until(time.Unix(0, v.Expiration)))
	}
}
