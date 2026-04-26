package secrets

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenCacheReturnsRefreshedToken(t *testing.T) {
	cache := newTokenCache(30 * time.Second)

	token, err := cache.GetOrRefresh(context.Background(), func(_ context.Context) (string, time.Time, error) {
		return "tok_123", time.Now().Add(1 * time.Hour), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "tok_123" {
		t.Errorf("got %q, want tok_123", token)
	}
}

func TestTokenCacheCachesToken(t *testing.T) {
	cache := newTokenCache(30 * time.Second)
	var calls atomic.Int32

	refresh := func(_ context.Context) (string, time.Time, error) {
		calls.Add(1)
		return "tok_cached", time.Now().Add(1 * time.Hour), nil
	}

	cache.GetOrRefresh(context.Background(), refresh)
	cache.GetOrRefresh(context.Background(), refresh)
	cache.GetOrRefresh(context.Background(), refresh)

	if calls.Load() != 1 {
		t.Errorf("expected 1 refresh call, got %d", calls.Load())
	}
}

func TestTokenCacheRefreshesExpired(t *testing.T) {
	cache := &tokenCache{
		token:  "old",
		expiry: time.Now().Add(-1 * time.Hour),
		margin: 30 * time.Second,
	}

	token, err := cache.GetOrRefresh(context.Background(), func(_ context.Context) (string, time.Time, error) {
		return "new", time.Now().Add(1 * time.Hour), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "new" {
		t.Errorf("got %q, want new", token)
	}
}

func TestTokenCacheRefreshesWithinMargin(t *testing.T) {
	cache := &tokenCache{
		token:  "expiring_soon",
		expiry: time.Now().Add(10 * time.Second),
		margin: 30 * time.Second,
	}

	token, err := cache.GetOrRefresh(context.Background(), func(_ context.Context) (string, time.Time, error) {
		return "refreshed", time.Now().Add(1 * time.Hour), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "refreshed" {
		t.Errorf("got %q, want refreshed", token)
	}
}

func TestTokenCacheZeroExpiryNeverExpires(t *testing.T) {
	cache := &tokenCache{
		token:  "forever",
		expiry: time.Time{},
		margin: 30 * time.Second,
	}

	token, err := cache.GetOrRefresh(context.Background(), func(_ context.Context) (string, time.Time, error) {
		t.Fatal("refresh should not be called")
		return "", time.Time{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "forever" {
		t.Errorf("got %q, want forever", token)
	}
}

func TestTokenCacheTTL(t *testing.T) {
	cache := &tokenCache{
		token:  "tok",
		expiry: time.Now().Add(30 * time.Minute),
		margin: 30 * time.Second,
	}
	ttl := cache.TTL()
	if ttl < 29*time.Minute || ttl > 31*time.Minute {
		t.Errorf("TTL = %v, want ~30m", ttl)
	}
}

func TestTokenCacheTTLExpired(t *testing.T) {
	cache := &tokenCache{
		token:  "tok",
		expiry: time.Now().Add(-1 * time.Hour),
		margin: 30 * time.Second,
	}
	if cache.TTL() != 0 {
		t.Errorf("expected 0 for expired, got %v", cache.TTL())
	}
}

func TestTokenCacheTTLZeroExpiry(t *testing.T) {
	cache := &tokenCache{
		token:  "tok",
		expiry: time.Time{},
		margin: 30 * time.Second,
	}
	if cache.TTL() != 0 {
		t.Errorf("expected 0 for zero expiry, got %v", cache.TTL())
	}
}

func TestTokenCachePropagatesError(t *testing.T) {
	cache := newTokenCache(30 * time.Second)

	_, err := cache.GetOrRefresh(context.Background(), func(_ context.Context) (string, time.Time, error) {
		return "", time.Time{}, fmt.Errorf("auth failed")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "auth failed" {
		t.Errorf("got %q", err)
	}
}

func TestTokenCacheConcurrent(t *testing.T) {
	cache := newTokenCache(30 * time.Second)
	var calls atomic.Int32

	refresh := func(_ context.Context) (string, time.Time, error) {
		calls.Add(1)
		return "concurrent_tok", time.Now().Add(1 * time.Hour), nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := cache.GetOrRefresh(context.Background(), refresh)
			if err != nil {
				t.Errorf("error: %v", err)
				return
			}
			if token != "concurrent_tok" {
				t.Errorf("got %q", token)
			}
		}()
	}
	wg.Wait()
}
