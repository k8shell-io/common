package cache

import (
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
)

var (
	ErrCacheMiss = errors.New("cache: miss")
	ErrNotStored = errors.New("cache: not stored")
)

// BucketOptions holds options for the JetStream cache bucket.
type BucketOptions struct {
	Bucket    string           `yaml:"bucket" json:"bucket"`
	BucketTTL time.Duration    `yaml:"bucketTTL" json:"bucketTTL"`
	History   uint8            `yaml:"history" json:"history"`
	Storage   nats.StorageType `yaml:"storage" json:"storage"`
}

// JetStreamCache is a cache client backed by NATS JetStream KV store.
type JetStreamCache struct {
	log        *zerolog.Logger
	cfg        natsc.NATSClientConfig
	bucketOpts BucketOptions
	mu         sync.RWMutex
	nc         *nats.Conn
	js         nats.JetStreamContext
	kv         nats.KeyValue
}

// entryEnvelope wraps cached data with optional expiration. It allows per-entry TTLs.
type entryEnvelope struct {
	ExpireAt int64  `json:"exp,omitempty"` // unix seconds
	Data     []byte `json:"d"`
}

// lockEnvelope holds lock owner and expiration.
type lockEnvelope struct {
	Owner    string `json:"owner,omitempty"`
	ExpireAt int64  `json:"exp,omitempty"` // unix seconds
}

// JSLock is a guard returned by TryAcquireLock.
// Call Release() when done.
type JSLock struct {
	c      *JetStreamCache
	key    string
	owner  string
	acqRev uint64
}

// NewJetStreamCache connects to NATS, ensures/binds the KV bucket.
func NewJetStreamCache(cfg natsc.NATSClientConfig, bucketOpts BucketOptions) (Cache, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	l := logger.NewLogger("cache")

	opts := natsc.NatsOptionsFromConfig("k8shell-cache", cfg)
	if bucketOpts.Bucket == "" {
		return nil, errors.New("cache: bucket name required")
	}
	if bucketOpts.History == 0 {
		bucketOpts.History = 1
	}
	if bucketOpts.BucketTTL == 0 {
		bucketOpts.BucketTTL = 24 * time.Hour
	}

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
			// Re-create JS context and re-bind KV bucket on reconnect
			if js, err := nc.JetStream(); err == nil {
				c.mu.Lock()
				c.nc = nc
				c.js = js
				if kv, e2 := js.KeyValue(c.bucketOpts.Bucket); e2 == nil {
					c.kv = kv
				}
				c.mu.Unlock()
			}
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			c.log.Warn().Msg("NATS connection closed")
		}),
	)

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect NATS: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}

	var kv nats.KeyValue
	kv, err = js.KeyValue(c.bucketOpts.Bucket)
	if err != nil {
		ttl := c.bucketOpts.BucketTTL
		kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
			Bucket:  c.bucketOpts.Bucket,
			History: c.bucketOpts.History,
			Storage: c.bucketOpts.Storage,
			TTL:     ttl,
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

// Get returns the raw cached bytes or ErrCacheMiss.
func (c *JetStreamCache) Get(key string) ([]byte, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return nil, errors.New("cache disabled")
	}
	e, err := kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}

	var env entryEnvelope
	if err := json.Unmarshal(e.Value(), &env); err != nil || len(env.Data) == 0 {
		raw := e.Value()
		if len(raw) == 0 {
			return nil, ErrCacheMiss
		}
		return raw, nil
	}
	if env.ExpireAt > 0 && time.Now().Unix() >= env.ExpireAt {
		_ = kv.Delete(key)
		return nil, ErrCacheMiss
	}
	return env.Data, nil
}

// Set stores bytes with a per-key TTL (soft; enforced by envelope).
func (c *JetStreamCache) Set(key string, value []byte, ttl time.Duration) error {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return errors.New("cache disabled")
	}
	env := entryEnvelope{Data: value}
	if ttl > 0 {
		env.ExpireAt = time.Now().Add(ttl).Unix()
	}
	b, _ := json.Marshal(&env)
	_, err := kv.Put(key, b)
	return err
}

// Add stores only if key does not exist.
func (c *JetStreamCache) Add(key string, value []byte, ttl time.Duration) error {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return errors.New("cache disabled")
	}
	env := entryEnvelope{Data: value}
	if ttl > 0 {
		env.ExpireAt = time.Now().Add(ttl).Unix()
	}
	b, _ := json.Marshal(&env)
	_, err := kv.Create(key, b)
	if err != nil {
		if errors.Is(err, nats.ErrKeyExists) {
			return ErrNotStored
		}
		return err
	}
	return nil
}

// Delete removes a key (idempotent).
func (c *JetStreamCache) Delete(key string) error {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return errors.New("cache disabled")
	}
	err := kv.Delete(key)
	if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
		return err
	}
	return nil
}

func (c *JetStreamCache) SetString(key string, s string, ttl time.Duration) error {
	return c.Set(key, []byte(s), ttl)
}

func (c *JetStreamCache) GetString(key string) (string, error) {
	b, err := c.Get(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// TryAcquireLock attempts to acquire a lock at key with TTL.
// Returns ErrNotStored if the lock is already held and not expired.
// On success returns a guard; call guard.Release() to release.
// The lock is implemented using KV Create() and CAS Update() when taking over expired locks.
func (c *JetStreamCache) AcquireLock(key string, ttl time.Duration) (Lock, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return nil, errors.New("cache disabled")
	}

	now := time.Now()
	exp := int64(0)
	if ttl > 0 {
		exp = now.Add(ttl).Unix()
	}
	owner := randToken()
	payload, _ := json.Marshal(&lockEnvelope{Owner: owner, ExpireAt: exp})

	if rev, err := kv.Create(key, payload); err == nil {
		return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
	} else if !errors.Is(err, nats.ErrKeyExists) {
		return nil, err
	}

	// exists: loop a few times to try to take over if expired.
	for i := 0; i < 3; i++ {
		e, err := kv.Get(key)
		if err != nil {
			if errors.Is(err, nats.ErrKeyNotFound) {
				if rev, e2 := kv.Create(key, payload); e2 == nil {
					return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
				} else if !errors.Is(e2, nats.ErrKeyExists) {
					return nil, e2
				}
				continue
			}
			return nil, err
		}

		var cur lockEnvelope
		_ = json.Unmarshal(e.Value(), &cur)

		if cur.ExpireAt > 0 && now.Unix() >= cur.ExpireAt {
			if rev, err := kv.Update(key, payload, e.Revision()); err == nil {
				return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
			}
			continue
		}

		return nil, ErrNotStored
	}

	return nil, ErrNotStored
}

// Release attempts to release the lock by CAS-updating it to an empty owner and no expiration.
// It will only release if we still own the lock; otherwise it is a no-op.
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

	e, err := kv.Get(l.key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return nil
		}
		return err
	}

	var cur lockEnvelope
	_ = json.Unmarshal(e.Value(), &cur)
	if cur.Owner != l.owner {
		return nil
	}

	cur.Owner = ""
	cur.ExpireAt = 0
	b, _ := json.Marshal(&cur)

	_, _ = kv.Update(l.key, b, e.Revision())
	return nil
}

// randToken returns a random hex token for lock owner identity.
func randToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
