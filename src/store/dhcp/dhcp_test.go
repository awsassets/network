package dhcp_store

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Dhcp(t *testing.T) {
	dhcp := New()

	node := "test"
	node2 := "test2"

	ip := dhcp.NewIp(node)

	assert.Equal(t, ip, dhcp.NewIp(node), "Dhcp issues an ip to a node")

	ip = net.IPv4(10, 10, 0, 1).To4()

	dhcp.StoreIp(ip, node)
	dhcp.StoreIp(ip, node2)

	assert.NotEqual(t, ip, dhcp.NewIp(node), "Dhcp issues an ip to a node")

	items := dhcp.Serialize()
	dhcp.Merge(items)
}
