package main

import (
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/node"
	"github.com/disembark/network/src/modes/relay"
	"github.com/disembark/network/src/modes/signal/server"
	"github.com/sirupsen/logrus"
)

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
		server.New(config)
	default:
		logrus.Fatal("unknown mode")
	}
}
