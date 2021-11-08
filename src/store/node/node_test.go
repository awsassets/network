package node_store

import (
	"testing"

	dns_store "github.com/disembark/network/src/store/dns"
	"github.com/disembark/network/src/types"
	"github.com/stretchr/testify/assert"
)

func Test_Node(t *testing.T) {
	node := New()
	defer node.Stop()

	name := "test"
	pl := Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "test",
			IP:   "172.0.0.1",
		},
	}

	node.SetNode(name, pl)
	node.SetNode(name, pl)
	ret, ok := node.GetNode(name)
	assert.Equal(t, true, ok, "The node is stored")
	assert.Equal(t, pl, ret, "The node is stored")

	ret, ok = node.GetNode("not_valid_name")
	assert.Equal(t, false, ok, "The node is not stored")
	assert.Equal(t, Node{}, ret, "The node is not stored")

	node.Merge(node.Serialize())

	node.Stop()
}

func Test_NodeDns(t *testing.T) {
	node := New()
	defer node.Stop()

	name := "test"
	pl := Node{
		JoinPayloadNode: types.JoinPayloadNode{
			Name: "test",
			IP:   "172.0.0.1",
			DnsAliases: []string{
				"test",
			},
		},
	}

	node.SetNode(name, pl)
	ret, ok := node.GetNode(name)
	assert.Equal(t, true, ok, "The node is stored")
	assert.Equal(t, pl, ret, "The node is stored")

	ret, ok = node.GetNode("not_valid_name")
	assert.Equal(t, false, ok, "The node is not stored")
	assert.Equal(t, Node{}, ret, "The node is not stored")

	node2 := NewWithDns(dns_store.New("127.1.0.53:53"))
	defer node2.Stop()

	node2.Merge(node.Serialize())

	ret, ok = node2.GetNode(name)
	assert.Equal(t, true, ok, "The node is stored")
	assert.Equal(t, pl, ret, "The node is stored")

	node2.SetNode(name, pl)

	node.SetNode(name, pl)

	node2.Merge(node.Serialize())

	node.Stop()
	node2.Stop()
}
