package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/k8shell-io/common/pkg/logger"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/rs/zerolog"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var (
	ErrCacheMiss = errors.New("cache: miss")
	ErrNotStored = errors.New("cache: not stored")
)

// BucketOptions holds options for the JetStream cache bucket.
type BucketOptions struct {
	Bucket    string                `yaml:"bucket" json:"bucket"`
	BucketTTL time.Duration         `yaml:"bucketTTL" json:"bucketTTL"`
	History   uint8                 `yaml:"history" json:"history"`
	Storage   jetstream.StorageType `yaml:"storage" json:"storage"`
	Replicas  int                   `yaml:"replicas" json:"replicas"`
}

// JetStreamCache is a cache client backed by NATS JetStream KV store.
type JetStreamCache struct {
	log        *zerolog.Logger
	cfg        natsc.NATSClientConfig
	bucketOpts BucketOptions

	mu sync.RWMutex
	nc *nats.Conn
	js jetstream.JetStream
	kv jetstream.KeyValue
}

type lockEnvelope struct {
	Owner    string `json:"owner,omitempty"`
	ExpireAt int64  `json:"exp,omitempty"` // unix seconds
}

type JSLock struct {
	c      *JetStreamCache
	key    string
	owner  string
	acqRev uint64
}

func NewJetStreamCache(cfg natsc.NATSClientConfig, bucketOpts BucketOptions) (Cache, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	l := logger.NewLogger("cache")

	if bucketOpts.Bucket == "" {
		return nil, errors.New("cache: bucket name required")
	}
	if bucketOpts.History == 0 {
		bucketOpts.History = 1
	}
	if bucketOpts.Replicas == 0 {
		bucketOpts.Replicas = 1
	}

	opts := natsc.NatsOptionsFromConfig("k8shell-cache", cfg)
	c := &JetStreamCache{log: l, cfg: cfg, bucketOpts: bucketOpts}

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
			js, err := jetstream.New(nc)
			if err != nil {
				return
			}
			c.mu.Lock()
			c.js = js
			if kv, e2 := js.KeyValue(context.Background(), c.bucketOpts.Bucket); e2 == nil {
				c.kv = kv
			}
			c.mu.Unlock()
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			c.log.Warn().Msg("NATS connection closed")
		}),
	)

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect NATS: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}

	ctx := context.Background()

	kv, err := js.KeyValue(ctx, bucketOpts.Bucket)
	if err != nil {
		kv, err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
			Bucket:         bucketOpts.Bucket,
			TTL:            bucketOpts.BucketTTL,
			History:        bucketOpts.History,
			Storage:        bucketOpts.Storage,
			Replicas:       bucketOpts.Replicas,
			LimitMarkerTTL: time.Duration(30) * time.Second,
		})
		if err != nil {
			nc.Close()
			return nil, fmt.Errorf("create KV bucket: %w", err)
		}
	}

	c.mu.Lock()
	c.nc, c.js, c.kv = nc, js, kv
	c.mu.Unlock()

	c.log.Info().
		Str("bucket", c.bucketOpts.Bucket).
		Str("url", cfg.URL).
		Msg("JetStream KV cache ready")

	return c, nil
}

func (c *JetStreamCache) Close() {
	c.mu.Lock()
	if c.nc != nil {
		c.nc.Drain()
		c.nc.Close()
	}
	c.nc = nil
	c.js = nil
	c.kv = nil
	c.mu.Unlock()
}

func (c *JetStreamCache) Get(key string) ([]byte, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return nil, errors.New("cache disabled")
	}
	e, err := kv.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}
	val := e.Value()
	if len(val) == 0 {
		return nil, ErrCacheMiss
	}
	return val, nil
}

// Set stores bytes with a per-key TTL (set on create) or updates existing value.
// Per-key TTL can only be set at Create-time. If the key exists, Update() will
// reset the existing TTL countdown but cannot change the duration.
func (c *JetStreamCache) Set(key string, value []byte, ttl time.Duration) error {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return errors.New("cache disabled")
	}

	ctx := context.Background()

	var opts []jetstream.KVCreateOpt
	if ttl > 0 {
		opts = append(opts, jetstream.KeyTTL(ttl))
	}
	if _, err := kv.Create(ctx, key, value, opts...); err == nil {
		return nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return err
	}

	// Key exists: fetch revision and Update (resets countdown if key already had TTL).
	e, err := kv.Get(ctx, key)
	if err != nil {
		return err
	}
	_, err = kv.Update(ctx, key, value, e.Revision())
	return err
}

// Add stores only if key does not exist; applies per-key TTL on create.
func (c *JetStreamCache) Add(key string, value []byte, ttl time.Duration) error {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return errors.New("cache disabled")
	}
	ctx := context.Background()
	var opts []jetstream.KVCreateOpt
	if ttl > 0 {
		opts = append(opts, jetstream.KeyTTL(ttl))
	}
	_, err := kv.Create(ctx, key, value, opts...)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			return ErrNotStored
		}
		return err
	}
	return nil
}

func (c *JetStreamCache) Delete(key string) error {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return errors.New("cache disabled")
	}
	ctx := context.Background()
	err := kv.Delete(ctx, key)
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return err
	}
	return nil
}

func (c *JetStreamCache) SetString(key, s string, ttl time.Duration) error {
	return c.Set(key, []byte(s), ttl)
}

func (c *JetStreamCache) GetString(key string) (string, error) {
	b, err := c.Get(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// AcquireLock implements a KV-based lock with TTL using CAS.
func (c *JetStreamCache) AcquireLock(key string, ttl time.Duration) (Lock, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return nil, errors.New("cache disabled")
	}

	ctx := context.Background()
	now := time.Now()
	exp := int64(0)
	if ttl > 0 {
		exp = now.Add(ttl).Unix()
	}
	owner := randToken()
	payload, _ := json.Marshal(&lockEnvelope{Owner: owner, ExpireAt: exp})

	// Create (fast path)
	if rev, err := kv.Create(ctx, key, payload); err == nil {
		return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return nil, err
	}

	// Exists: attempt take-over if expired.
	for i := 0; i < 3; i++ {
		e, err := kv.Get(ctx, key)
		if err != nil {
			if errors.Is(err, jetstream.ErrKeyNotFound) {
				if rev, e2 := kv.Create(ctx, key, payload); e2 == nil {
					return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
				} else if !errors.Is(e2, jetstream.ErrKeyExists) {
					return nil, e2
				}
				continue
			}
			return nil, err
		}

		var cur lockEnvelope
		_ = json.Unmarshal(e.Value(), &cur)

		if cur.ExpireAt > 0 && now.Unix() >= cur.ExpireAt {
			if rev, err := kv.Update(ctx, key, payload, e.Revision()); err == nil {
				return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
			}
			continue
		}
		return nil, ErrNotStored
	}
	return nil, ErrNotStored
}

func (l *JSLock) Release() error {
	if l == nil || l.c == nil {
		return nil
	}
	l.c.mu.RLock()
	kv := l.c.kv
	l.c.mu.RUnlock()
	if kv == nil {
		return nil
	}

	ctx := context.Background()
	e, err := kv.Get(ctx, l.key)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil
		}
		return err
	}

	var cur lockEnvelope
	_ = json.Unmarshal(e.Value(), &cur)
	if cur.Owner != l.owner {
		return nil
	}
	cur.Owner, cur.ExpireAt = "", 0
	b, _ := json.Marshal(&cur)
	_, _ = kv.Update(ctx, l.key, b, e.Revision())
	return nil
}

func randToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
