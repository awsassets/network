package node

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/disembark/network/src/modes/node/packet"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

func CreateTun(rawIP string) *water.Interface {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalln("failed to create tun interface:", err)
	}
	log.Println("interface created:", iface.Name())
	configTun(rawIP, iface)
	return iface
}

func configTun(rawIP string, iface *water.Interface) {
	os := runtime.GOOS
	rawIP = fmt.Sprintf("%s/16", rawIP)
	_, _, err := net.ParseCIDR(rawIP)
	if err != nil {
		logrus.Fatal("bad ip: ", err)
	}
	if os == "linux" {
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "mtu", fmt.Sprint(packet.MTU))
		execCmd("/sbin/ip", "addr", "add", rawIP, "dev", iface.Name())
		execCmd("/sbin/ip", "link", "set", "dev", iface.Name(), "up")
	} else {
		logrus.Fatal("not support os: ", os)
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
