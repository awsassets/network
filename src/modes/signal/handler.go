package signal

import (
	"net"

	"github.com/davecgh/go-spew/spew"
	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/helpers"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/fasthttp/websocket"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	node_store "github.com/disembark/network/src/store/node"
)

type WriteFunction func(types.Message) error

func (s *Server) Handler(ctx *fasthttp.RequestCtx) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Error("panic in handler: ", err)
		}
	}()

	mode := configure.Mode(utils.B2S(ctx.Request.Header.Peek("mode")))

	switch mode {
	case configure.ModeNode, configure.ModeSignal, configure.ModeRelayClient, configure.ModeRelayServer:
	default:
		ctx.SetStatusCode(404)
		return
	}

	tkn, err := helpers.VerifyClientJoinToken(s.config, utils.B2S(ctx.Request.Header.Peek("authentication")))
	if err != nil {
		logrus.Error("bad token: ", err.Error())
		ctx.SetStatusCode(403)
		return
	}

	if tkn.Mode != mode {
		ctx.SetStatusCode(403)
		return
	}

	eventID, _ := uuid.NewRandom()
	s.events.Register(eventID.String())

	var handler websocket.FastHTTPHandler

	switch mode {
	case configure.ModeNode, configure.ModeRelayClient:
		handler = s.nodeHandler(tkn, ctx.Request.Header.Peek("node"), mode == configure.ModeRelayClient)
	case configure.ModeSignal:
		handler = s.signalHandler(tkn, ctx.Request.Header.Peek("signal"))
	case configure.ModeRelayServer:
		if tkn.Name == utils.B2S(ctx.Request.Header.Peek("name")) {
			handler = s.relayHandler(tkn)
		}
	}

	if handler == nil {
		ctx.SetStatusCode(400)
		return
	}

	if err := s.upgrader.Upgrade(ctx, handler); err != nil {
		logrus.Error("failed to upgrade connection: ", err)
		ctx.SetStatusCode(400)
	}
}

func (s *Server) BroadcastNodes(msg types.Message) {
	// this will send a message to all nodes connected to this signal server
	s.nodeConnections.Range(func(key, value interface{}) bool {
		_ = value.(WriteFunction)(msg)
		return true
	})
}

func (s *Server) BroadcastSignal(msg types.Message) {
	// this will send a message to all signal servers connected to this signal server
	s.signalConnections.Range(func(key, value interface{}) bool {
		_ = value.(WriteFunction)(msg)
		return true
	})

	// this will send a message to all signal servers this signal server is connected to
	s.signal.Broadcast(msg)
}

func (s *Server) Broadcast(msg types.Message) {
	s.BroadcastNodes(msg)
	s.BroadcastSignal(msg)
}

func (s *Server) nodeHandler(tkn types.JoinTokenPayload, raw []byte, relay bool) websocket.FastHTTPHandler {
	pl := types.JoinPayloadNode{}
	if err := json.Unmarshal(raw, &pl); err != nil {
		return nil
	}

	if pl.Name != tkn.Name {
		return nil
	}

	dynamic := true

	if pl.IP != "dynamic" {
		dynamic = false
		ip := net.ParseIP(pl.IP).To4()
		if ip == nil || !(ip[0] == 10 && ip[1] == 10 && ip[2] <= 10) {
			return nil
		}
	}

	pl.Relay = relay

	return func(c *websocket.Conn) {
		if pl.IP == "dynamic" {
			pl.IP = s.dhcp.NewIp(pl.Name).String()
		} else {
			ip := net.ParseIP(pl.IP).To4()
			pl.IP = ip.String()
			if v, ok := s.node.GetNode(pl.IP); ok && v.Name != pl.Name {
				pl.IP = s.dhcp.NewIp(pl.Name).String()
			}
		}

		logrus.Debug("new node: ", tkn.Name)
		rid := utils.OrPanic(utils.GenerateRandomString(32))[0].(string)
		write := WriteFunction(func(m types.Message) error {
			data, _ := json.Marshal(m)
			return c.WriteMessage(websocket.TextMessage, data)
		})
		s.nodeConnections.Store(rid, write)
		defer s.nodeConnections.Delete(rid)

		_ = write(types.Message{
			Type: types.MessageTypeNodeState,
			Payload: utils.OrPanic(json.Marshal(types.MessageNodeState{
				Nodes: s.node.Serialize(),
				Signals: append(s.config.SignalServers, configure.SignalServer{
					Name:         s.config.Name,
					AccessPoints: s.config.AdvertiseAddresses,
				}),
				Current: pl,
			}))[0].([]byte),
		})

		registerNode := func() {
			msg := types.Message{}
			// this is a ping which refreshes our current state of the node in the cache
			s.node.SetNode(pl.Name, node_store.Node{JoinPayloadNode: pl})
			// at this point we not only have to refresh our own internal cache but also must inform all other signals and nodes about the cache refresh
			// so we must iterate over the map. first we must do nodes followed by signals. We must also create an event for this.
			id, _ := uuid.NewRandom()
			s.events.Register(id.String())

			msg.Key = id.String()
			msg.Type = types.MessageTypeNodeRegister
			msg.Payload = utils.OrPanic(json.Marshal(types.MessageNodeRegister{
				Node:      pl,
				DynamicIP: dynamic,
			}))[0].([]byte)

			s.Broadcast(msg)
		}

		registerNode()

		var (
			err  error
			data []byte
		)
		msg := types.Message{}
		for {
			_, data, err = c.ReadMessage()
			if err != nil {
				return
			}
			err = json.Unmarshal(data, &msg)
			if err != nil {
				return
			}
			switch msg.Type {
			case types.MessageTypePing:
				registerNode()

				msg.Payload = nil
				msg.Key = ""
				msg.Type = types.MessageTypePong
				err = write(msg)
				if err != nil {
					return
				}
			}
		}
	}
}

func (s *Server) signalHandler(tkn types.JoinTokenPayload, raw []byte) websocket.FastHTTPHandler {
	pl := types.JoinPayloadSignal{}
	if err := json.Unmarshal(raw, &pl); err != nil {
		return nil
	}

	if pl.Name != tkn.Name {
		return nil
	}

	return func(c *websocket.Conn) {
		rid := utils.OrPanic(utils.GenerateRandomString(32))[0].(string)
		write := WriteFunction(func(m types.Message) error {
			data, _ := json.Marshal(m)
			return c.WriteMessage(websocket.TextMessage, data)
		})
		s.signalConnections.Store(rid, write)
		defer s.signalConnections.Delete(rid)

		data, _ := json.Marshal(types.Message{
			Type: types.MessageTypeSignalState,
			Payload: utils.OrPanic(json.Marshal(types.MessageSignalState{
				Nodes: s.node.Serialize(),
				Signals: append(s.config.SignalServers, configure.SignalServer{
					Name:         s.config.Name,
					AccessPoints: s.config.AdvertiseAddresses,
				}),
				DHCP: s.dhcp.Serialize(),
			}))[0].([]byte),
		})
		_ = c.WriteMessage(websocket.TextMessage, data)

		logrus.Debug("new signal: ", tkn.Name)

		msg := types.Message{}
		var err error
		for {
			_, data, err = c.ReadMessage()
			if err != nil {
				return
			}
			err = json.Unmarshal(data, &msg)
			if err != nil {
				return
			}
			switch msg.Type {
			case types.MessageTypePing:
				msg.Payload = nil
				msg.Key = ""
				msg.Type = types.MessageTypePong
				err = write(msg)
				if err != nil {
					return
				}
			case types.MessageTypeNodeRegister:
				// these are all events that we need to forward to our clients.
				// make sure we cannot register this event twice.
				if s.events.Register(msg.Key) {
					continue
				}

				pl := types.MessageNodeRegister{}
				if err := json.Unmarshal(msg.Payload, &pl); err != nil {
					continue
				}

				// store the node in our cache
				s.node.SetNode(pl.Node.Name, node_store.Node{JoinPayloadNode: pl.Node})
				// if the ip is dynamic ie. defined by our dhcp impl then we must reserve this ip for future connections.
				if pl.DynamicIP {
					s.dhcp.StoreIp(net.ParseIP(pl.Node.IP), pl.Node.Name)
				}

				// redistrobute the message to all connections.
				s.Broadcast(msg)
			case types.MessageTypeSignalRegister:
				// these are all events that we need to forward to our clients.
				// make sure we cannot register this event twice.
				if s.events.Register(msg.Key) {
					continue
				}
				// We need to be careful here sometimes we can in theory collide 2 networks, lets say we have 3 nodes, none are connected.
				// One signal connects to another which has the ip 10.10.0.1 bound to a node. Then another signal has the same ip bound but to a different node.
				// And then the middle signal is restarted to connect to both 1 and 3, when both 1 and  3 have that ip allocated to different nodes.
				// 1 and 3 will then connect and there will be a collision and this isnt easily solved. A possible solution is when a collision is detected to restart both nodes.
				// that seems to be the best way to resolve it.
				pl := types.MessageSignalRegister{}
				if err := json.Unmarshal(msg.Payload, &pl); err != nil {
					continue
				}

				// merge the other states
				s.node.Merge(pl.Signal.Nodes)
				s.dhcp.Merge(pl.Signal.DHCP)

				// the first thing we must do is check if the signal connecting is new or if it is already registered.
				found := false
				changed := false
				for i, sig := range s.config.SignalServers {
					if sig.Name == pl.Signal.Name {
						found = true
						if len(sig.AccessPoints) != len(pl.Signal.AccessPoints) {
							s.config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
							_ = s.config.Save()
							changed = true
						} else {
							for i, a := range sig.AccessPoints {
								if pl.Signal.AccessPoints[i] != a {
									s.config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
									_ = s.config.Save()
									changed = true
									break
								}
							}
						}
						break
					}
				}
				if !found {
					// this is a new node.
					s.config.SignalServers = append(s.config.SignalServers, pl.Signal.SignalServer)
					_ = s.config.Save()
					changed = true
				}
				if changed {
					// the signal server has changed, we must re-register it.
					s.BroadcastSignal(msg)
					pl.Signal.DHCP = nil
					msg.Payload = utils.OrPanic(json.Marshal(pl))[0].([]byte)
					// remove the dhcp part
					s.BroadcastNodes(msg)

					tkn, err := helpers.GenerateClientJoinToken(s.config, configure.ModeSignal, s.config.Name)
					if err != nil {
						logrus.Fatal("failed to generate join token: ", err)
					}

					s.signal.Register(pl.Signal.SignalServer, tkn)
				}
				// we now need to look at the other signal servers that this node has registered.
				for _, v := range pl.Signal.Signals {
					found = false
					changed = false
					for i, sig := range s.config.SignalServers {
						if sig.Name == pl.Signal.Name {
							found = true
							if len(sig.AccessPoints) != len(pl.Signal.AccessPoints) {
								s.config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
								_ = s.config.Save()
								changed = true
							} else {
								for i, a := range sig.AccessPoints {
									if pl.Signal.AccessPoints[i] != a {
										s.config.SignalServers[i].AccessPoints = pl.Signal.AccessPoints
										_ = s.config.Save()
										changed = true
										break
									}
								}
							}
							break
						}
					}
					if !found {
						// this is a new node.
						s.config.SignalServers = append(s.config.SignalServers, pl.Signal.SignalServer)
						_ = s.config.Save()
						changed = true
					}
					if changed {
						// the signal server has changed, we must re-register it.

						tkn, err := helpers.GenerateClientJoinToken(s.config, configure.ModeSignal, s.config.Name)
						if err != nil {
							logrus.Fatal("failed to generate join token: ", err)
						}

						s.signal.Register(v, tkn)
					}
				}
			case types.MessageTypeSignalDeregister:
				// these are all events that we need to forward to our clients.
				// make sure we cannot register this event twice.
				if s.events.Register(msg.Key) {
					continue
				}
				s.Broadcast(msg)
				// currently unsupported
				logrus.Warn("unsupported endpoint payload: ", spew.Sdump(msg))
			}
		}
	}
}

func (s *Server) relayHandler(tkn types.JoinTokenPayload) websocket.FastHTTPHandler {
	return func(c *websocket.Conn) {
		rid := utils.OrPanic(utils.GenerateRandomString(32))[0].(string)
		write := WriteFunction(func(m types.Message) error {
			data, _ := json.Marshal(m)
			return c.WriteMessage(websocket.TextMessage, data)
		})
		s.signalConnections.Store(rid, write)
		defer s.signalConnections.Delete(rid)

		data, _ := json.Marshal(types.Message{
			Type: types.MessageTypeNodeState,
			Payload: utils.OrPanic(json.Marshal(types.MessageNodeState{
				Nodes: s.node.Serialize(),
				Signals: append(s.config.SignalServers, configure.SignalServer{
					Name:         s.config.Name,
					AccessPoints: s.config.AdvertiseAddresses,
				}),
			}))[0].([]byte),
		})
		_ = c.WriteMessage(websocket.TextMessage, data)

		logrus.Debug("new relay-server: ", tkn.Name)

		msg := types.Message{}
		var err error
		for {
			_, data, err = c.ReadMessage()
			if err != nil {
				return
			}
			err = json.Unmarshal(data, &msg)
			if err != nil {
				return
			}
			switch msg.Type {
			case types.MessageTypePing:
				msg.Payload = nil
				msg.Key = ""
				msg.Type = types.MessageTypePong
				err = write(msg)
				if err != nil {
					return
				}
			}
		}
	}
}
