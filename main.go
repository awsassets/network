package main

import (
	"runtime/debug"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/node"
	"github.com/disembark/network/src/modes/signal/server"
	"github.com/sirupsen/logrus"
)

func init() {
	debug.SetGCPercent(2000)
}

func main() {
	config := configure.New()

	switch config.Mode {
	case configure.ModeNode:
		node.New(config)
	case configure.ModeRelayServer:
		// relayServer.New(config)
	case configure.ModeRelayClient:
		// relayClient.New(config)
	case configure.ModeSignal:
		server.New(config)
	default:
		logrus.Fatal("unknown mode: ", config.Mode)
	}
}
