package main

import (
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/bugsnag/panicwrap"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/elevated"
	"github.com/disembark/network/src/modes/node"
	"github.com/disembark/network/src/modes/relay"
	"github.com/disembark/network/src/modes/signal"

	"github.com/sirupsen/logrus"
)

var (
	Version = "development"
	Unix    = ""
	Time    = "unknown"
	User    = "unknown"
)

func init() {
	debug.SetGCPercent(2000)
	if i, err := strconv.Atoi(Unix); err == nil {
		Time = time.Unix(int64(i), 0).Format(time.RFC3339)
	}
}

func main() {
	config := configure.New()

	exitStatus, err := panicwrap.BasicWrap(func(s string) {
		logrus.Error(s)
	})
	if err != nil {
		logrus.Error("failed to setup panic handler: ", err)
		os.Exit(2)
	}

	if exitStatus >= 0 {
		os.Exit(exitStatus)
	}

	if !config.NoHeader {
		logrus.Info("DisembarkNetwork a P2P VPC")
		logrus.Infof("Version:\t\t%s", Version)
		logrus.Infof("build.Time:\t%s", Time)
		logrus.Infof("build.User:\t%s\n\n", User)
	}

	if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/C", "title", "Disembark Network").Run()
	}

	logrus.Debug("MaxProcs: ", runtime.GOMAXPROCS(0))

	switch config.Mode {
	case configure.ModeNode:
		if !elevated.IsElevated() {
			logrus.Fatal("this program requires elevated permissions to run")
		}
		node.New(config)
	case configure.ModeRelayServer:
		relay.NewServer(config)
	case configure.ModeRelayClient:
		if !elevated.IsElevated() {
			logrus.Fatal("this program requires elevated permissions to run")
		}
		relay.NewClient(config)
	case configure.ModeSignal:
		signal.NewServer(config)
	default:
		logrus.Fatal("unknown mode: ", config.Mode)
	}
}
