package secrets

import (
	"context"
	"sync"
	"time"
)

type tokenCache struct {
	mu     sync.RWMutex
	token  string
	expiry time.Time
	margin time.Duration
}

func newTokenCache(margin time.Duration) *tokenCache {
	return &tokenCache{margin: margin}
}

// valid reports whether the cached token is still usable.
// Must be called with mu held (read or write).
func (c *tokenCache) valid() bool {
	if c.token == "" {
		return false
	}
	if c.expiry.IsZero() {
		return true
	}
	return time.Now().Before(c.expiry.Add(-c.margin))
}

func (c *tokenCache) GetOrRefresh(ctx context.Context, refresh func(ctx context.Context) (string, time.Time, error)) (string, error) {
	c.mu.RLock()
	if c.valid() {
		token := c.token
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.valid() {
		return c.token, nil
	}

	token, expiry, err := refresh(ctx)
	if err != nil {
		return "", err
	}
	c.token = token
	c.expiry = expiry
	return token, nil
}
