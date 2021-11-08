package network

import (
	"os/exec"

	"github.com/sirupsen/logrus"
)

type NetworkInterface interface {
	SetIP(ip string)
	GetRaws() []Device
	GetIndex(idx int) Device
	GetNext() Device
	ConfigureDNS() (string, error)
	Name() string
	Stop() error
}

func CreateTun() NetworkInterface {
	return createTun()
}

func execCmd(c string, args ...string) ([]byte, error) {
	logrus.Debugf("exec cmd: %s %v:", c, args)
	return exec.Command(c, args...).Output()
}
