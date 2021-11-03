package node

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"

	sig "os/signal"

	"github.com/disembark/network/src/base"
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/modes/signal"
	"github.com/disembark/network/src/netutil"
	"github.com/disembark/network/src/packet"

	"github.com/sirupsen/logrus"
)

type Node struct {
	*base.Client
}

func New(config *configure.Config) {
	logrus.Info("starting node")
	ctx, cancel := context.WithCancel(context.Background())

	ch := make(chan os.Signal, 1)

	sig.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	node := &Node{
		Client: base.NewClient(config),
	}

	node.SignalClient = signal.NewClient(ctx, config, config.AdvertiseAddresses)

	done := make(chan struct{})
	go func() {
		<-ch
		go func() {
			select {
			case <-ch:
			case <-time.After(time.Minute):
			}
			logrus.Fatal("force shutdown")
		}()
		cancel()

		<-node.SignalClient.Done()

		close(done)
	}()

	go node.ProcessSignal()

	udpConns, err := netutil.ListenUDP(config.Bind)
	if err != nil {
		logrus.Fatal("failed to listen to udp: ", err)
	}

	for _, v := range udpConns {
		defer v.Close()

		go node.ListenConn(v)
	}

	tcpConns, err := netutil.ListenTCP(config.Bind)
	if err != nil {
		logrus.Fatal("failed to listen to tcp: ", err)
	}

	for _, v := range tcpConns {
		defer v.Close()

		go node.ListenTCP(v)
	}

	<-done

	logrus.Info("shutdown")
	os.Exit(0)
}

func (r *Node) ListenConn(conn net.Conn) {
	defer conn.Close()

	pc := packet.NewConstructor()

	for {
		switch c := conn.(type) {
		case *net.UDPConn:
			addr, err := pc.ReadUDP(c)
			if err != nil {
				logrus.Warn("failed to read udp: ", err)
				continue
			}

			r.HandlePacket(pc, conn, addr, true, false)
		case *net.TCPConn:
			if err := pc.ReadTCP(c); err != nil {
				return
			}
			r.HandlePacket(pc, conn, nil, false, false)
		}
	}
}

func (r *Node) ListenTCP(ln *net.TCPListener) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			continue
		}
		go r.ListenConn(conn)
	}
}
