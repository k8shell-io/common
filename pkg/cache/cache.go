package cache

import (
	"context"
	"encoding/json"
)

type Lock interface {
	Release() error
}

// Fetch: same semantics as before, now on top of JS KV.
// On miss, calls fetch(), caches result with TTL, and returns it.
func Fetch[T any](ctx context.Context, cache *JetStreamCache, key string,
	fetch func(context.Context) (T, error),
) (T, error) {
	var zero T
	if cache == nil {
		return fetch(ctx)
	}
	if b, err := cache.Get(key); err == nil && len(b) > 0 {
		if _, ok := any(zero).([]byte); ok {
			cp := append([]byte(nil), b...)
			return any(cp).(T), nil
		}
		if _, ok := any(zero).(string); ok {
			return any(string(b)).(T), nil
		}
		var v T
		if err := json.Unmarshal(b, &v); err == nil {
			return v, nil
		}
	}

	v, err := fetch(ctx)
	if err != nil {
		return zero, err
	}

	switch vv := any(v).(type) {
	case []byte:
		_ = cache.Set(key, vv)
	case string:
		_ = cache.Set(key, []byte(vv))
	default:
		if b, mErr := json.Marshal(v); mErr == nil {
			_ = cache.Set(key, b)
		}
	}
	return v, nil
}
