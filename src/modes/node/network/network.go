package network

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/disembark/network/src/modes/node/packet"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

type NetworkInterface struct {
	raw *water.Interface
	ip  string
	mtx sync.Mutex
}

func CreateTun() *NetworkInterface {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		logrus.Fatal("failed to create tun interface: ", err)
	}
	n := &NetworkInterface{
		raw: iface,
	}
	n.configTun()
	return n
}

func (n *NetworkInterface) SetIP(ip string) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	ip = fmt.Sprintf("%s/16", ip)
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		logrus.Fatal("bad ip: ", err)
	}

	if n.ip != "" {
		execCmd("/sbin/ip", "addr", "del", n.ip, "dev", n.raw.Name())
	}

	switch runtime.GOOS {
	case "linux":
		execCmd("/sbin/ip", "addr", "add", ip, "dev", n.raw.Name())
	default:
		logrus.Fatal("not support os: ", runtime.GOOS)
	}

	n.ip = ip
}

func (n *NetworkInterface) GetRaw() *water.Interface {
	return n.raw
}

func (n *NetworkInterface) configTun() {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	switch runtime.GOOS {
	case "linux":
		execCmd("/sbin/ip", "link", "set", "dev", n.raw.Name(), "mtu", fmt.Sprint(packet.MTU))
		execCmd("/sbin/ip", "addr", "add", "10.10.0.0", "dev", n.raw.Name(), "scope", "host")
		execCmd("/sbin/ip", "link", "set", "dev", n.raw.Name(), "up")
		execCmd("/usr/bin/systemd-resolve", "--set-dns", "10.10.0.0", "--set-domain", "internal.disembark", "--interface", n.raw.Name())
	default:
		logrus.Fatal("not support os: ", runtime.GOOS)
	}
}

func execCmd(c string, args ...string) {
	logrus.Debugf("exec cmd: %s %v:", c, args)
	cmd := exec.Command(c, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		logrus.Fatalln("failed to exec cmd: ", err)
	}
}
