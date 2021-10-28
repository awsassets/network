package dhcp

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/patrickmn/go-cache"
)

type DHCP struct {
	cache *cache.Cache
	rand  *rand.Rand
}

func New() *DHCP {
	return &DHCP{
		rand:  rand.New(rand.NewSource(time.Now().UnixNano())),
		cache: cache.New(time.Hour*24, time.Hour),
	}
}

func (d *DHCP) NewIp(node string) net.IP {
	if ip, ok := d.GetNode(node); ok {
		d.cache.SetDefault(node, ip.String())
		d.cache.SetDefault(ip.String(), node)
		return ip
	}
	var ip string
	for {
		ip = fmt.Sprintf("10.10.%d.%d", d.rand.Int31n(245)+10, d.rand.Int31n(254)+1)
		if _, ok := d.cache.Get(ip); !ok {
			break
		}
	}

	d.cache.SetDefault(node, ip)
	d.cache.SetDefault(ip, node)

	return net.ParseIP(ip)
}

func (d *DHCP) StoreIp(ip net.IP, node string) {
	ip = ip.To4()
	if oIP, ok := d.cache.Get(node); ok {
		d.cache.Delete(oIP.(string))
	}
	d.cache.SetDefault(node, ip.String())
	d.cache.SetDefault(ip.String(), node)
}

func (d *DHCP) GetNode(node string) (net.IP, bool) {
	if v, ok := d.cache.Get(node); ok {
		return net.ParseIP(v.(string)).To4(), true
	}

	return nil, false
}

func (d *DHCP) Serialize() map[string]cache.Item {
	return d.cache.Items()
}

func (d *DHCP) Merge(items map[string]cache.Item) {
	for k, v := range items {
		if v.Expired() {
			continue
		}
		if _, t, ok := d.cache.GetWithExpiration(k); ok && t.After(time.Unix(0, v.Expiration)) {
			continue
		}
		d.cache.Set(k, v.Object, time.Until(time.Unix(0, v.Expiration)))
	}
}
