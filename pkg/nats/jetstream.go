package nats

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/nats-io/nats.go"
)

// BucketOptions holds options for the JetStream cache bucket.
type BucketOptions struct {
	Bucket    string           `yaml:"bucket" json:"bucket"`
	BucketTTL time.Duration    `yaml:"bucketTTL" json:"bucketTTL"`
	History   uint8            `yaml:"history" json:"history"`
	Storage   nats.StorageType `yaml:"storage" json:"storage"`
	Replicas  int              `yaml:"replicas" json:"replicas"`
}

// JetStreamKV is a cache client backed by NATS JetStream KV store.
type JetStreamKV struct {
	log        *zerolog.Logger
	bucketOpts BucketOptions

	kv nats.KeyValue
	mu sync.RWMutex
}

// lockEnvelope holds lock owner and expiration.
type lockEnvelope struct {
	Owner    string `json:"owner,omitempty"`
	ExpireAt int64  `json:"exp,omitempty"` // unix seconds
}

// JSLock is a guard returned by AcquireLock. Call Release() when done.
type JSLock struct {
	c      *JetStreamKV
	key    string
	owner  string
	acqRev uint64
}

func setKVDefaults(o *BucketOptions) {
	if o.History == 0 {
		o.History = 1
	}
	if o.BucketTTL == 0 {
		o.BucketTTL = 24 * time.Hour
	}
	if o.Replicas <= 0 {
		o.Replicas = 3
	}
}

func (c *NATSClient) NewKV(bucketOpts BucketOptions) (*JetStreamKV, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if bucketOpts.Bucket == "" {
		return nil, errors.New("cache: bucket name required")
	}
	setKVDefaults(&bucketOpts)

	var err error

	if c.nc == nil {
		return nil, fmt.Errorf("NATS connection is not established")
	}
	if c.js == nil {
		c.js, err = c.nc.JetStream()
		if err != nil {
			return nil, err
		}
	}

	jkv := &JetStreamKV{log: c.log, bucketOpts: bucketOpts, mu: sync.RWMutex{}}

	jkv.kv, err = c.js.KeyValue(bucketOpts.Bucket)
	if err != nil {
		jkv.kv, err = c.js.CreateKeyValue(&nats.KeyValueConfig{
			Bucket:      bucketOpts.Bucket,
			History:     bucketOpts.History,
			Storage:     bucketOpts.Storage,
			TTL:         bucketOpts.BucketTTL,
			Replicas:    bucketOpts.Replicas,
			Placement:   nil,
			Description: "",
		})
		if err != nil {
			return nil, fmt.Errorf("create KV bucket: %w", err)
		}
	}

	return jkv, nil
}

// Get retrieves raw bytes at key.
func (c *JetStreamKV) Get(key string) (nats.KeyValueEntry, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return nil, nats.ErrConnectionClosed
	}
	e, err := kv.Get(key)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Set stores raw bytes at key.
func (c *JetStreamKV) Set(key string, value []byte) (uint64, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return 0, nats.ErrConnectionClosed
	}
	r, err := kv.Put(key, value)
	if err != nil {
		return 0, err
	}
	return r, nil
}

// Create stores raw bytes at key only if missing. Returns nats.ErrKeyExists if already present.
func (c *JetStreamKV) Create(key string, value []byte) (uint64, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return 0, nats.ErrConnectionClosed
	}
	r, err := kv.Create(key, value)
	return r, err
}

func (c *JetStreamKV) Update(key string, value []byte, revision uint64) (uint64, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return 0, nats.ErrConnectionClosed
	}
	r, err := kv.Update(key, value, revision)
	if err != nil {
		return 0, err
	}
	return r, nil
}

// Delete removes a key. Returns nats.ErrKeyNotFound if missing.
func (c *JetStreamKV) Delete(key string) error {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return nats.ErrConnectionClosed
	}
	return kv.Delete(key)
}

// AcquireLock attempts to acquire a lock at key with TTL.
// Returns nats.ErrKeyExists if the lock is already held and not expired.
// On success returns a guard; call guard.Release() to release.
// Implemented using KV Create() and CAS Update() when taking over expired locks.
func (c *JetStreamKV) AcquireLock(key string, ttl time.Duration) (*JSLock, error) {
	c.mu.RLock()
	kv := c.kv
	c.mu.RUnlock()
	if kv == nil {
		return nil, nats.ErrConnectionClosed
	}

	now := time.Now()
	exp := int64(0)
	if ttl > 0 {
		exp = now.Add(ttl).Unix()
	}
	owner := randToken()
	payload, _ := json.Marshal(&lockEnvelope{Owner: owner, ExpireAt: exp})

	// create if not exists
	if rev, err := kv.Create(key, payload); err == nil {
		return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
	} else if !errors.Is(err, nats.ErrKeyExists) {
		return nil, err
	}

	// Exists: try to take over if expired
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

		// If expired, CAS to take over
		if cur.ExpireAt > 0 && now.Unix() >= cur.ExpireAt {
			if rev, err := kv.Update(key, payload, e.Revision()); err == nil {
				return &JSLock{c: c, key: key, owner: owner, acqRev: rev}, nil
			}
			// lost race; retry
			continue
		}

		// still held
		return nil, nats.ErrKeyExists
	}

	return nil, nats.ErrKeyExists
}

// Release attempts to release the lock by CAS-updating it to empty owner/no expiration.
// It only releases if we still own the lock; otherwise it is a no-op.
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
