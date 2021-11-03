package types

import (
	"time"

	"github.com/disembark/network/src/configure"
)

type JoinPayloadNode struct {
	Name               string   `json:"name"`
	AdvertiseAddresses []string `json:"advertise_addresses"`
	DnsAliases         []string `json:"dns_aliases"`
	PublicKey          string   `json:"public_key"`
	IP                 string   `json:"ip"`
	Relay              bool     `json:"relay"`
}

type JoinPayloadSignal struct {
	Name               string                   `json:"name"`
	AdvertiseAddresses []string                 `json:"advertise_addresses"`
	SignalServers      []configure.SignalServer `json:"signal_servers"`
}

type JoinTokenPayload struct {
	CreatedAt time.Time      `json:"created_at"`
	Mode      configure.Mode `json:"mode"`
	Name      string         `json:"name"`
}
