package nats

import (
	"time"

	"github.com/nats-io/nats.go"
)

// NATSClientConfig holds NATS connection.
type NATSClientConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	URL           string        `yaml:"url" json:"url"`
	Username      string        `yaml:"username" json:"username"`
	Password      string        `yaml:"password" json:"password"`
	Token         string        `yaml:"token"    json:"token"`
	MaxReconnects int           `yaml:"maxReconnects" json:"maxReconnects"`
	ReconnectWait time.Duration `yaml:"reconnectWait" json:"reconnectWait"`
}

func NatsOptionsFromConfig(name string, cfg NATSClientConfig) []nats.Option {
	opts := []nats.Option{
		nats.Name(name),
	}
	if cfg.Token != "" {
		opts = append(opts, nats.Token(cfg.Token))
	} else if cfg.Username != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}
	if cfg.MaxReconnects == 0 {
		cfg.MaxReconnects = -1 // infinite
	}
	if cfg.ReconnectWait == 0 {
		cfg.ReconnectWait = 2 * time.Second
	}
	opts = append(opts,
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.ReconnectWait(cfg.ReconnectWait),
	)
	return opts
}
