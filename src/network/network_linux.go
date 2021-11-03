//go:build linux

package network

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/disembark/network/src/loadbalancer"
	"github.com/disembark/network/src/packet"
	"github.com/disembark/network/src/utils"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

var nameServerRegex = regexp.MustCompile(`^nameserver ((?:[012]?[0-9]?[0-9])\.(?:[012]?[0-9]?[0-9])\.(?:[012]?[0-9]?[0-9])\.(?:[012]?[0-9]?[0-9])(?::\d+)?)`)

type linuxTun struct {
	lb   *loadbalancer.LoadBalancer
	ip   string
	mtx  sync.Mutex
	name string
}

func createTun() *linuxTun {
	extra := runtime.GOMAXPROCS(0) - 1

	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			MultiQueue: extra != 0,
		},
	}

	iface, err := water.New(cfg)
	if err != nil {
		logrus.Fatal("failed to create tun interface: ", err)
	}

	cfg.Name = iface.Name()

	raws := make([]interface{}, 1+extra)

	raws[0] = iface

	for i := 0; i < extra; i++ {
		iface, err := water.New(cfg)
		if err != nil {
			logrus.Fatal("failed to create tun interface: ", err)
		}

		raws[1+i] = iface
	}

	n := &linuxTun{
		lb:   loadbalancer.NewLoadBalancer(raws...),
		name: iface.Name(),
	}

	n.configTun()
	return n
}

func (n *linuxTun) SetIP(ip string) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	ip = fmt.Sprintf("%s/16", ip)
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		logrus.Fatal("bad ip: ", err)
	}

	if n.ip != "" {
		_, err = execCmd("/sbin/ip", "addr", "del", n.ip, "dev", n.name)
		if err != nil {
			logrus.Fatal("failed to configure tun: ", err)
		}
	}

	_, err = execCmd("/sbin/ip", "addr", "add", ip, "dev", n.name)
	if err != nil {
		logrus.Fatal("failed to configure tun: ", err)
	}

	n.ip = ip
}

func (n *linuxTun) GetRaws() []Device {
	items := n.lb.GetItems()

	devs := make([]Device, len(items))
	for i, v := range items {
		devs[i] = v.(Device)
	}

	return devs
}

func (n *linuxTun) GetIndex(idx int) Device {
	return n.lb.GetItem(idx).(Device)
}

func (n *linuxTun) GetNext() Device {
	return n.lb.GetNext().(Device)
}

func (n *linuxTun) configTun() {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	_, err := execCmd("/sbin/ip", "link", "set", "dev", n.name, "mtu", fmt.Sprint(packet.MTU))
	if err != nil {
		logrus.Fatal("failed to configure tun: ", err)
	}
	_, err = execCmd("/sbin/ip", "addr", "add", "172.10.0.53/32", "dev", n.name, "scope", "host")
	if err != nil {
		logrus.Fatal("failed to configure tun: ", err)
	}
	_, err = execCmd("/sbin/ip", "link", "set", "dev", n.name, "up")
	if err != nil {
		logrus.Fatal("failed to configure tun: ", err)
	}
}

func (n *linuxTun) ConfigureDNS() (string, error) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	// try using the systemd-resolve
	_, err := os.Stat("/usr/bin/systemd-resolve")
	if err == nil {
		_, err = execCmd("/usr/bin/systemd-resolve", "--set-dns", "172.10.0.53:53", "--set-domain", "internal.disembark", "--interface", n.name)
		if err == nil {
			return "", nil
		}
	}

	// resort back to using resolv.conf
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}

	proxy := ""

	lines := strings.Split(utils.B2S(content), "\n")
	refinedLines := []string{"", "", ""}
	for _, l := range lines {
		if !strings.Contains(l, "# disembark auto generated") {
			refinedLines = append(refinedLines, l)
			matches := nameServerRegex.FindAllStringSubmatch(l, 1)
			if proxy == "" && len(matches) == 1 {
				proxy = matches[0][1]
			}
		}
	}

	// then we need to add 2 new lines
	refinedLines[0] = "search internal.disembark # disembark auto generated"
	refinedLines[1] = "nameserver 172.10.0.53 # disembark auto generated"

	if v, ok := os.LookupEnv("DISEMBARK_DNS_PROXY"); ok {
		proxy = v
		refinedLines[3] = fmt.Sprintf("nameserver %s # disembark auto generated\n", v)
	}

	if proxy == "" {
		proxy = "1.1.1.1:53"
	}

	if !strings.Contains(proxy, ":") {
		proxy = proxy + ":53"
	}

	return proxy, os.WriteFile("/etc/resolv.conf", utils.S2B(strings.Join(refinedLines, "\n")), 0600)
}

func (n *linuxTun) Name() string {
	return n.name
}
