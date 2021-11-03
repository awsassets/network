package main

import (
	"runtime"
	"runtime/debug"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/node"
	"github.com/disembark/network/src/modes/relay"
	"github.com/disembark/network/src/modes/signal"

	"github.com/sirupsen/logrus"
)

func init() {
	debug.SetGCPercent(2000)
	logrus.Info("MaxProcs: ", runtime.GOMAXPROCS(0))
}

func main() {
	config := configure.New()

	switch config.Mode {
	case configure.ModeNode:
		node.New(config)
	case configure.ModeRelayServer:
		relay.NewServer(config)
	case configure.ModeRelayClient:
		relay.NewClient(config)
	case configure.ModeSignal:
		signal.NewServer(config)
	default:
		logrus.Fatal("unknown mode: ", config.Mode)
	}
}
