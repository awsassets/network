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

func checkErr(err error) {
	if err != nil {
		logrus.WithError(err).Fatal("config")
	}
}

func New() *Config {
	config := viper.New()
	config.SetConfigType("yaml")

	b, err := defaultJson.Marshal(Config{
		LogLevel:   "info",
		ConfigFile: "config.yaml",
	})

	checkErr(err)
	tmp := viper.New()
	tmp.SetConfigType("json")
	checkErr(tmp.ReadConfig(bytes.NewBuffer(b)))
	checkErr(config.MergeConfigMap(tmp.AllSettings()))

	pflag.String("config_file", "config.yaml", "Config file location")
	pflag.String("create", "", "create a client/signal/relay-client/relay-server instance")
	pflag.String("create_name", "", "name of the instanced created by --create")
	pflag.Parse()
	checkErr(config.BindPFlags(pflag.CommandLine))

	config.SetConfigFile(config.GetString("config_file"))
	if config.ReadInConfig() == nil {
		checkErr(config.MergeInConfig())
	}

	cfg := Config{}

	config.SetEnvPrefix(".")
	config.AllowEmptyEnv(true)
	config.AutomaticEnv()

	checkErr(config.Unmarshal(&cfg))

	InitLogging(cfg.LogLevel)

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

	if cfg.ConfigFile != "" {
		config.SetConfigFile(cfg.ConfigFile)
		if config.ReadInConfig() == nil {
			checkErr(config.MergeInConfig())
		}
	}

	c := Config{}

	checkErr(config.Unmarshal(&c))

	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	InitLogging(cfg.LogLevel)

	_ = cfg.Save()

	return &cfg
}

type Config struct {
	// standard
	LogLevel   string `json:"log_level,omitempty" mapstructure:"log_level,omitempty" node:"log_level" signal:"log_level"`
	Mode       Mode   `json:"mode,omitempty" mapstructure:"mode,omitempty" node:"mode" signal:"mode"`
	ConfigFile string `json:"config_file,omitempty" mapstructure:"config_file,omitempty" node:"-" signal:"-"`
	Create     Mode   `json:"create,omitempty" mapstructure:"create,omitempty" node:"-" signal:"-"`
	CreateName string `json:"create_name,omitempty" mapstructure:"create_name,omitempty" node:"-" signal:"-"`

	// client only
	TunBind          string   `json:"tun_bind,omitempty" mapstructure:"tun_bind,omitempty" node:"tun_bind" signal:"-"`
	DnsAliases       []string `json:"dns_aliases,omitempty" mapstructure:"dns_aliases,omitempty" node:"dns_aliases" signal:"-"`
	ClientPublicKey  string   `json:"client_public_key,omitempty" mapstructure:"client_public_key,omitempty" node:"client_public_key" signal:"-"`
	ClientPrivateKey string   `json:"client_private_key,omitempty" mapstructure:"client_private_key,omitempty" node:"client_private_key" signal:"-"`
	JoinToken        string   `json:"join_token,omitempty" mapstructure:"join_token,omitempty" node:"join_token" signal:"-"`

	// client or signal
	Bind                  string         `json:"bind,omitempty" mapstructure:"bind,omitempty" node:"bind" signal:"bind"`
	AdvertiseAddresses    []string       `json:"advertise_addresses,omitempty" mapstructure:"advertise_addresses,omitempty" node:"advertise_addresses" signal:"advertise_addresses"`
	SignalServers         []SignalServer `json:"signal_servers,omitempty" mapstructure:"signal_servers,omitempty" node:"signal_servers" signal:"signal_servers"`
	SignalServerPublicKey string         `json:"signal_server_public_key,omitempty" mapstructure:"signal_server_public_key,omitempty" node:"signal_server_public_key" signal:"signal_server_public_key"`
	Name                  string         `json:"name,omitempty" mapstructure:"name,omitempty" node:"name" signal:"name"`

	// signal only
	SignalServerPrivateKey string `json:"signal_server_private_key,omitempty" mapstructure:"signal_server_private_key,omitempty" node:"-" signal:"signal_server_private_key"`
	TokenKey               string `json:"token_key,omitempty" mapstructure:"token_key,omitempty" node:"-" signal:"token_key"`
}

type SignalServer struct {
	Name         string   `json:"name,omitempty" mapstructure:"name,omitempty" node:"name" signal:"name"`
	AccessPoints []string `json:"access_points,omitempty" mapstructure:"access_points,omitempty" node:"access_points" signal:"access_points"`
}

type Mode string

const (
	ModeNode        Mode = "node"
	ModeSignal      Mode = "signal"
	ModeRelayServer Mode = "relay-server"
	ModeRelayClient Mode = "relay-client"
)

func (s *Config) Save() error {
	if s.ConfigFile == "" {
		return nil
	}

	var json jsoniter.API

	switch s.Mode {
	case ModeNode:
		json = nodeJson
	case ModeRelayServer:
		json = defaultJson
	case ModeRelayClient:
		json = defaultJson
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
	tmp.SetConfigFile(s.ConfigFile)

	return tmp.WriteConfig()
}
