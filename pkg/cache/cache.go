package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/k8shell-io/common/pkg/logger"
	"github.com/rs/zerolog"
)

type ClientConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
}

type Cache struct {
	log      *zerolog.Logger
	config   ClientConfig
	memcache *memcache.Client
	mu       sync.RWMutex
}

func NewClient(config ClientConfig) *Cache {
	if !config.Enabled {
		return nil
	}

	var mc *memcache.Client
	if config.Enabled {
		mc = memcache.New(config.Address + ":" + strconv.Itoa(config.Port))
	}

	return &Cache{
		log:      logger.NewLogger("cache"),
		config:   config,
		memcache: mc,
	}
}

func (c *Cache) Memcache() *memcache.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.memcache
}

// recreateClient replaces the underlying memcache client.
func (c *Cache) recreateClient() {
	addr := c.config.Address + ":" + strconv.Itoa(c.config.Port)
	c.mu.Lock()
	c.memcache = memcache.New(addr)
	c.mu.Unlock()
	c.log.Warn().Str("addr", addr).Msg("Memcache client recreated")
}

// GetWithRetry does Get, on failure recreates client and retries once.
// ErrCacheMiss is returned as-is without recreating.
func (c *Cache) GetWithRetry(key string) (*memcache.Item, error) {
	c.mu.RLock()
	mc := c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return nil, fmt.Errorf("memcache disabled")
	}

	it, err := mc.Get(key)
	if err == nil || err == memcache.ErrCacheMiss {
		return it, err
	}

	c.log.Warn().Err(err).Str("key", key).Msg("Memcache Get failed; recreating client and retrying once")
	c.recreateClient()

	c.mu.RLock()
	mc = c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return nil, err
	}
	return mc.Get(key)
}

// SetWithRetry does Set, on failure recreates client and retries once.
func (c *Cache) SetWithRetry(it *memcache.Item) error {
	c.mu.RLock()
	mc := c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return fmt.Errorf("memcache disabled")
	}

	if err := mc.Set(it); err == nil {
		return nil
	} else {
		c.log.Warn().Err(err).Str("key", it.Key).Msg("Memcache Set failed; recreating client and retrying once")
	}

	c.recreateClient()

	c.mu.RLock()
	mc = c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return fmt.Errorf("memcache disabled after recreate")
	}
	return mc.Set(it)
}

// DeleteWithRetry deletes a key. On failure it recreates the client and retries once.
// ErrCacheMiss is treated as success (idempotent delete).
func (c *Cache) DeleteWithRetry(key string) error {
	c.mu.RLock()
	mc := c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return fmt.Errorf("memcache disabled")
	}

	if err := mc.Delete(key); err == nil || err == memcache.ErrCacheMiss {
		return nil
	} else {
		c.log.Warn().Err(err).Str("key", key).Msg("Memcache Delete failed; recreating client and retrying once")
	}

	c.recreateClient()

	c.mu.RLock()
	mc = c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return fmt.Errorf("memcache disabled after recreate")
	}

	if err := mc.Delete(key); err == memcache.ErrCacheMiss {
		return nil
	} else {
		return err
	}
}

// Fetch gets a value from memcached, or calls fetch() on miss,
// then stores it with the given TTL. Encoding/decoding is done via JSON or directly for []byte and string types.
func Fetch[T any](ctx context.Context, cache *Cache, key string, ttl time.Duration,
	fetch func(context.Context) (T, error),
) (T, error) {
	var zero T

	if cache == nil {
		return fetch(ctx)
	}

	cache.mu.RLock()
	disabled := cache.memcache == nil
	cache.mu.RUnlock()
	if disabled {
		cache.log.Debug().Msg("Memcache is not enabled, fetching directly")
		return fetch(ctx)
	}

	if it, err := cache.GetWithRetry(key); err == nil && it != nil && len(it.Value) > 0 {
		cache.log.Debug().Str("key", key).Msg("Found in cache")
		if _, ok := any(zero).([]byte); ok {
			cp := append([]byte(nil), it.Value...)
			return any(cp).(T), nil
		}
		if _, ok := any(zero).(string); ok {
			return any(string(it.Value)).(T), nil
		}

		var v T
		if err := json.Unmarshal(it.Value, &v); err == nil {
			return v, nil
		}
		cache.log.Warn().Err(err).Str("key", key).Msg("Failed to unmarshal cached value")
	} else if err != nil && err != memcache.ErrCacheMiss {
		cache.log.Warn().Err(err).Str("key", key).Msg("Get from cache failed")
	}

	v, err := fetch(ctx)
	if err != nil {
		cache.log.Warn().Err(err).Str("key", key).Msg("Failed to fetch value")
		return zero, err
	}

	var bytes []byte
	switch vv := any(v).(type) {
	case []byte:
		bytes = vv
	case string:
		bytes = []byte(vv)
	default:
		if b, mErr := json.Marshal(v); mErr == nil {
			bytes = b
		} else {
			cache.log.Warn().Err(mErr).Str("key", key).Msg("Failed to marshal value for caching")
			return v, nil
		}
	}

	_ = cache.SetWithRetry(&memcache.Item{
		Key:        key,
		Value:      bytes,
		Expiration: int32(ttl / time.Second),
	})

	return v, nil
}
