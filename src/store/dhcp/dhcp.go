package dhcp_store

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/disembark/network/src/cache"
)

type Store interface {
	NewIp(node string) net.IP
	StoreIp(ip net.IP, node string)
	GetNode(node string) (net.IP, bool)
	Serialize() []cache.CacheItem
	Merge(items []cache.CacheItem)
}

type DhcpStore struct {
	cache cache.Cache
	rand  *rand.Rand
}

type MockDhcpStore struct {
	NewIpFunc     func(node string) net.IP
	StoreIpFunc   func(ip net.IP, node string)
	GetNodeFunc   func(node string) (net.IP, bool)
	SerializeFunc func() []cache.CacheItem
	MergeFunc     func(items []cache.CacheItem)
}

func (d MockDhcpStore) NewIp(node string) net.IP {
	return d.NewIpFunc(node)
}

func (d MockDhcpStore) StoreIp(ip net.IP, node string) {
	d.StoreIpFunc(ip, node)
}

func (d MockDhcpStore) GetNode(node string) (net.IP, bool) {
	return d.GetNodeFunc(node)
}

func (d MockDhcpStore) Serialize() []cache.CacheItem {
	return d.SerializeFunc()
}

func (d MockDhcpStore) Merge(items []cache.CacheItem) {
	d.MergeFunc(items)
}

func New() Store {
	return &DhcpStore{
		rand:  rand.New(rand.NewSource(time.Now().UnixNano())),
		cache: cache.New(time.Hour, time.Hour*24),
	}
}

func (d *DhcpStore) NewIp(node string) net.IP {
	if ip, ok := d.GetNode(node); ok {
		d.cache.Store(node, ip.String())
		d.cache.Store(ip.String(), node)
		return ip.To4()
	}

	var ip string
	for {
		ip = fmt.Sprintf("10.10.%d.%d", d.rand.Int31n(245)+10, d.rand.Int31n(254)+1)
		if _, ok := d.cache.Get(ip); !ok {
			break
		}
	}

	d.cache.Store(node, ip)
	d.cache.Store(ip, node)

	return net.ParseIP(ip).To4()
}

func (d *DhcpStore) StoreIp(ip net.IP, node string) {
	ip = ip.To4()
	if oIP, ok := d.cache.Get(node); ok {
		d.cache.Delete(oIP.(string))
	}
	if oNode, ok := d.cache.Get(ip.String()); ok {
		d.cache.Delete(oNode.(string))
	}
	d.cache.Store(node, ip.String())
	d.cache.Store(ip.String(), node)
}

func (d *DhcpStore) GetNode(node string) (net.IP, bool) {
	if v, ok := d.cache.Get(node); ok {
		return net.ParseIP(v.(string)).To4(), true
	}

	return nil, false
}

func (d *DhcpStore) Serialize() []cache.CacheItem {
	return d.cache.ItemsArray()
}

func (d *DhcpStore) Merge(items []cache.CacheItem) {
	for _, v := range items {
		if v.Expired() {
			continue
		}
		d.cache.Merge(v)
	}
}
