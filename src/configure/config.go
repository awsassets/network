package configure

import (
	"bytes"

	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var defaultJson = jsoniter.ConfigCompatibleWithStandardLibrary

var nodeJson = jsoniter.Config{
	EscapeHTML:             true,
	SortMapKeys:            true,
	ValidateJsonRawMessage: true,
	TagKey:                 "node",
}.Froze()

var signalJson = jsoniter.Config{
	EscapeHTML:             true,
	SortMapKeys:            true,
	ValidateJsonRawMessage: true,
	TagKey:                 "signal",
}.Froze()

var relayServerJson = jsoniter.Config{
	EscapeHTML:             true,
	SortMapKeys:            true,
	ValidateJsonRawMessage: true,
	TagKey:                 "relay_server",
}.Froze()

var relayClientJson = jsoniter.Config{
	EscapeHTML:             true,
	SortMapKeys:            true,
	ValidateJsonRawMessage: true,
	TagKey:                 "relay_client",
}.Froze()

func checkErr(err error) {
	if err != nil {
		logrus.WithError(err).Fatal("config")
	}
}

func New() *Config {
	config := viper.New()
	config.SetConfigType("yaml")

	b, err := defaultJson.Marshal(Config{
		LogLevel: "info",
		Config:   "config.yaml",
	})

	checkErr(err)
	tmp := viper.New()
	tmp.SetConfigType("json")
	checkErr(tmp.ReadConfig(bytes.NewBuffer(b)))
	checkErr(config.MergeConfigMap(tmp.AllSettings()))

	pflag.String("config", "config.yaml", "Config file location")
	pflag.String("logs", "logs", "Directory to contain log files")
	pflag.String("create", "", "create a client/signal/relay-client/relay-server instance")
	pflag.String("create_name", "", "name of the instanced created by --create")
	pflag.Bool("noheader", false, "Disable the startup header")
	pflag.Parse()
	checkErr(config.BindPFlags(pflag.CommandLine))

	config.SetConfigFile(config.GetString("config"))
	if err := config.ReadInConfig(); err == nil {
		checkErr(config.MergeInConfig())
	}

	cfg := Config{}

	config.SetEnvPrefix(".")
	config.AllowEmptyEnv(true)
	config.AutomaticEnv()

	checkErr(config.Unmarshal(&cfg))

	initLogging(cfg.Logs, cfg.Name, cfg.LogLevel)

	checkErr(cfg.Save())

	return &cfg
}

func NewFromFile(cfg Config) *Config {
	config := viper.New()
	config.SetConfigType("yaml")

	b, err := defaultJson.Marshal(cfg)

	checkErr(err)
	tmp := viper.New()
	tmp.SetConfigType("json")
	checkErr(tmp.ReadConfig(bytes.NewBuffer(b)))
	checkErr(config.MergeConfigMap(tmp.AllSettings()))

	if cfg.Config != "" {
		config.SetConfigFile(cfg.Config)
		if config.ReadInConfig() == nil {
			checkErr(config.MergeInConfig())
		}
	}

	c := Config{}

	checkErr(config.Unmarshal(&c))

	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	_ = cfg.Save()

	return &cfg
}

type Config struct {
	// standard
	LogLevel string `json:"log_level,omitempty" mapstructure:"log_level,omitempty" node:"log_level" signal:"log_level" relay_server:"log_level" relay_client:"log_level"`
	Mode     Mode   `json:"mode,omitempty" mapstructure:"mode,omitempty" node:"mode" signal:"mode" relay_server:"mode" relay_client:"mode"`

	Config     string `json:"config,omitempty" mapstructure:"config,omitempty" node:"-" signal:"-" relay_server:"-" relay_client:"-"`
	Create     Mode   `json:"create,omitempty" mapstructure:"create,omitempty" node:"-" signal:"-" relay_server:"-" relay_client:"-"`
	CreateName string `json:"create_name,omitempty" mapstructure:"create_name,omitempty" node:"-" signal:"-" relay_server:"-" relay_client:"-"`
	Logs       string `json:"logs,omitempty" mapstructure:"logs,omitempty" node:"-" signal:"-" relay_server:"-" relay_client:"-"`
	NoHeader   bool   `json:"noheader,omitempty" mapstructure:"noheader,omitempty" node:"-" signal:"-" relay_server:"-" relay_client:"-"`

	// client only
	TunBind          string   `json:"tun_bind,omitempty" mapstructure:"tun_bind,omitempty" node:"tun_bind" signal:"-" relay_server:"-" relay_client:"tun_bind"`
	DnsAliases       []string `json:"dns_aliases,omitempty" mapstructure:"dns_aliases,omitempty" node:"dns_aliases" signal:"-" relay_server:"-" relay_client:"dns_aliases"`
	ClientPublicKey  string   `json:"client_public_key,omitempty" mapstructure:"client_public_key,omitempty" node:"client_public_key" signal:"-"  relay_server:"-" relay_client:"client_public_key"`
	ClientPrivateKey string   `json:"client_private_key,omitempty" mapstructure:"client_private_key,omitempty" node:"client_private_key" signal:"-" relay_server:"-" relay_client:"client_private_key"`
	JoinToken        string   `json:"join_token,omitempty" mapstructure:"join_token,omitempty" node:"join_token" signal:"-" relay_server:"-" relay_client:"join_token"`

	// client or signal
	Bind                  string         `json:"bind,omitempty" mapstructure:"bind,omitempty" node:"bind" signal:"bind" relay_server:"bind" relay_client:"-"`
	AdvertiseAddresses    []string       `json:"advertise_addresses,omitempty" mapstructure:"advertise_addresses,omitempty" node:"advertise_addresses" signal:"advertise_addresses" relay_server:"advertise_addresses" relay_client:"-"`
	SignalServers         []SignalServer `json:"signal_servers,omitempty" mapstructure:"signal_servers,omitempty" node:"signal_servers" signal:"signal_servers" relay_server:"signal_servers" relay_client:"signal_servers"`
	SignalServerPublicKey string         `json:"signal_server_public_key,omitempty" mapstructure:"signal_server_public_key,omitempty" node:"signal_server_public_key" signal:"signal_server_public_key" relay_server:"signal_server_public_key" relay_client:"signal_server_public_key"`
	Name                  string         `json:"name,omitempty" mapstructure:"name,omitempty" node:"name" signal:"name"  relay_server:"name" relay_client:"name"`

	// signal only
	SignalServerPrivateKey string `json:"signal_server_private_key,omitempty" mapstructure:"signal_server_private_key,omitempty" node:"-" signal:"signal_server_private_key" relay_server:"signal_server_private_key" relay_client:"-"`
	TokenKey               string `json:"token_key,omitempty" mapstructure:"token_key,omitempty" node:"-" signal:"token_key" relay_server:"token_key" relay_client:"-"`

	// relay server only
	RelayHttpBind string `json:"relay_http_bind,omitempty" mapstructure:"relay_http_bind,omitempty" node:"-" signal:"-" relay_server:"relay_http_bind" relay_client:"-"`

	// relay client only
	RelayServerHttp string `json:"relay_server_http,omitempty" mapstructure:"relay_server_http,omitempty" node:"-" signal:"-" relay_server:"-" relay_client:"relay_server_http"`
	RelayServer     string `json:"relay_server,omitempty" mapstructure:"relay_server,omitempty" node:"-" signal:"-" relay_server:"-" relay_client:"relay_server"`
}

type SignalServer struct {
	Name         string   `json:"name,omitempty" mapstructure:"name,omitempty" node:"name" signal:"name" relay_server:"name" relay_client:"name"`
	AccessPoints []string `json:"access_points,omitempty" mapstructure:"access_points,omitempty" node:"access_points" signal:"access_points"  relay_server:"access_points" relay_client:"access_points"`
}

type Mode string

const (
	ModeNode        Mode = "node"
	ModeSignal      Mode = "signal"
	ModeRelayServer Mode = "relay-server"
	ModeRelayClient Mode = "relay-client"
)

func (s *Config) Save() error {
	if s.Config == "" {
		return nil
	}

	var json jsoniter.API

	switch s.Mode {
	case ModeNode:
		json = nodeJson
	case ModeRelayServer:
		json = relayServerJson
	case ModeRelayClient:
		json = relayClientJson
	case ModeSignal:
		json = signalJson
	default:
		json = jsoniter.ConfigCompatibleWithStandardLibrary
	}

	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	tmp := viper.New()
	tmp.SetConfigType("json")

	if err = tmp.ReadConfig(bytes.NewBuffer(b)); err != nil {
		return err
	}

	tmp.SetConfigType("yaml")
	tmp.SetConfigFile(s.Config)

	return tmp.WriteConfig()
}
