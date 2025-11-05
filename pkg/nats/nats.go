package nats

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/k8shell-io/common/pkg/logger"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
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

type NATSClient struct {
	log *zerolog.Logger
	mu  sync.RWMutex
	nc  *nats.Conn
	js  nats.JetStreamContext
}

type Lock interface {
	Release() error
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

func NewNATSClient(cfg NATSClientConfig) (*NATSClient, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	c := &NATSClient{
		nc:  nil,
		js:  nil,
		log: logger.NewLogger("nats"),
		mu:  sync.RWMutex{},
	}

	opts := NatsOptionsFromConfig("nats-client", cfg)
	opts = append(opts,
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				c.log.Warn().Err(err).Msg("NATS disconnected")
			} else {
				c.log.Warn().Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			c.log.Info().Str("url", nc.ConnectedUrl()).Msg("NATS reconnected")
			c.mu.Lock()
			c.nc = nc
			c.mu.Unlock()
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			c.log.Warn().Msg("NATS connection closed")
		}),
	)

	var err error
	c.nc, err = nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *NATSClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nc != nil {
		c.nc.Drain()
		c.nc.Close()
		c.nc = nil
		c.js = nil
	}
}

// Fetch: same semantics as before, now on top of JS KV.
// On miss, calls fetch(), caches result with TTL, and returns it.
func Fetch[T any](ctx context.Context, cache *JetStreamKV, key string,
	fetch func(context.Context) (T, error),
) (T, error) {
	var zero T
	if cache == nil {
		return fetch(ctx)
	}
	if b, err := cache.Get(key); err == nil && len(b.Value()) > 0 {
		if _, ok := any(zero).([]byte); ok {
			cp := append([]byte(nil), b.Value()...)
			return any(cp).(T), nil
		}
		if _, ok := any(zero).(string); ok {
			return any(string(b.Value())).(T), nil
		}
		var v T
		if err := json.Unmarshal(b.Value(), &v); err == nil {
			return v, nil
		}
	}

	v, err := fetch(ctx)
	if err != nil {
		return zero, err
	}

	switch vv := any(v).(type) {
	case []byte:
		_, _ = cache.Set(key, vv)
	case string:
		_, _ = cache.Set(key, []byte(vv))
	default:
		if b, mErr := json.Marshal(v); mErr == nil {
			_, _ = cache.Set(key, b)
		}
	}
	return v, nil
}

// randToken returns a random hex token for lock owner identity.
func randToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
