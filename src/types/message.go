package types

import (
	"github.com/disembark/network/src/cache"
	"github.com/disembark/network/src/configure"
	jsoniter "github.com/json-iterator/go"
)

type MessageType int32

const (
	// All Messages
	MessageTypePing MessageType = iota
	MessageTypePong

	// Events
	MessageTypeNodeRegister
	MessageTypeSignalRegister
	MessageTypeSignalDeregister

	// Node Messages
	MessageTypeNodeState

	// Signal Messages
	MessageTypeSignalState
)

// The general message structure
type Message struct {
	Type    MessageType         `json:"type"`
	Payload jsoniter.RawMessage `json:"payload,omitempty"`
	Key     string              `json:"key,omitempty"`
}

// Message payload when Type = MessageTypeNodeState
type MessageNodeState struct {
	Nodes   []cache.CacheItem        `json:"nodes"`
	Current JoinPayloadNode          `json:"current"`
	Signals []configure.SignalServer `json:"signals"`
}

// Message payload when Type = MessageTypeSignalState
type MessageSignalState struct {
	configure.SignalServer
	Nodes   []cache.CacheItem        `json:"nodes"`
	Signals []configure.SignalServer `json:"signals"`
	DHCP    []cache.CacheItem        `json:"dhcp,omitempty"`
}

type MessageNodeRegister struct {
	Node      JoinPayloadNode `json:"node"`
	DynamicIP bool            `json:"dynamic_ip"`
}

type MessageSignalRegister struct {
	Signal MessageSignalState `json:"state"`
}
