package cache

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/k8shell-io/common/pkg/logger"
	"github.com/rs/zerolog"
)

type MemcacheConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
}

type Memcache struct {
	log      *zerolog.Logger
	config   MemcacheConfig
	memcache *memcache.Client
	mu       sync.RWMutex
}

func NewClient(config MemcacheConfig) *Memcache {
	if !config.Enabled {
		return nil
	}

	var mc *memcache.Client
	if config.Enabled {
		mc = memcache.New(config.Address + ":" + strconv.Itoa(config.Port))
	}

	return &Memcache{
		log:      logger.NewLogger("memcache"),
		config:   config,
		memcache: mc,
	}
}

func (c *Memcache) Memcache() *memcache.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.memcache
}

// recreateClient replaces the underlying memcache client.
func (c *Memcache) recreateClient() {
	addr := c.config.Address + ":" + strconv.Itoa(c.config.Port)
	c.mu.Lock()
	c.memcache = memcache.New(addr)
	c.mu.Unlock()
	c.log.Warn().Str("addr", addr).Msg("Memcache client recreated")
}

// Get does Get, on failure recreates client and retries once.
// ErrCacheMiss is returned as-is without recreating.
func (c *Memcache) Get(key string) (*memcache.Item, error) {
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

// Set does Set, on failure recreates client and retries once.
func (c *Memcache) Set(it *memcache.Item) error {
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

// Delete deletes a key. On failure it recreates the client and retries once.
// ErrCacheMiss is treated as success (idempotent delete).
func (c *Memcache) Delete(key string) error {
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

// Add adds a key only if it does not already exist.
// On failure it recreates the client and retries once.
// ErrNotStored (key exists) is returned as-is without recreating.
func (c *Memcache) Add(it *memcache.Item) error {
	c.mu.RLock()
	mc := c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return fmt.Errorf("memcache disabled")
	}

	if err := mc.Add(it); err == nil || err == memcache.ErrNotStored {
		return err
	} else {
		c.log.Warn().Err(err).Str("key", it.Key).Msg("Memcache Add failed; recreating client and retrying once")
	}

	c.recreateClient()

	c.mu.RLock()
	mc = c.memcache
	c.mu.RUnlock()
	if mc == nil {
		return fmt.Errorf("memcache disabled after recreate")
	}

	err := mc.Add(it)
	if err == memcache.ErrNotStored {
		return err
	}
	return err
}
