package cache

import (
	"context"
	"encoding/json"
	"time"
)

type Cache interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte, ttl time.Duration) error
	Add(key string, value []byte, ttl time.Duration) error
	Delete(key string) error
	SetString(key string, s string, ttl time.Duration) error
	GetString(key string) (string, error)
}

// Fetch: same semantics as before, now on top of JS KV.
// On miss, calls fetch(), caches result with TTL, and returns it.
func Fetch[T any](ctx context.Context, cache Cache, key string, ttl time.Duration,
	fetch func(context.Context) (T, error),
) (T, error) {
	var zero T
	if cache == nil {
		return fetch(ctx)
	}
	// try from cache
	if b, err := cache.Get(key); err == nil && len(b) > 0 {
		// []byte fast-path
		if _, ok := any(zero).([]byte); ok {
			cp := append([]byte(nil), b...)
			return any(cp).(T), nil
		}
		// string fast-path
		if _, ok := any(zero).(string); ok {
			return any(string(b)).(T), nil
		}
		// JSON decode
		var v T
		if err := json.Unmarshal(b, &v); err == nil {
			return v, nil
		}
	}

	// miss or decode error -> fetch
	v, err := fetch(ctx)
	if err != nil {
		return zero, err
	}

	// encode & store
	switch vv := any(v).(type) {
	case []byte:
		_ = cache.Set(key, vv, ttl)
	case string:
		_ = cache.Set(key, []byte(vv), ttl)
	default:
		if b, mErr := json.Marshal(v); mErr == nil {
			_ = cache.Set(key, b, ttl)
		}
	}
	return v, nil
}
