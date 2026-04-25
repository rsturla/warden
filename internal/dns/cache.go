package dns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const defaultMaxCacheEntries = 4096

type CachingResolver struct {
	upstream   Resolver
	maxTTL     time.Duration
	maxEntries int
	mu         sync.RWMutex
	entries    map[string]*cacheEntry
	cacheHits  atomic.Int64
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func NewCachingResolver(upstream Resolver, maxTTL time.Duration) *CachingResolver {
	return &CachingResolver{
		upstream:   upstream,
		maxTTL:     maxTTL,
		maxEntries: defaultMaxCacheEntries,
		entries:    make(map[string]*cacheEntry),
	}
}

func (r *CachingResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	r.mu.RLock()
	if e, ok := r.entries[host]; ok && time.Now().Before(e.expires) {
		r.mu.RUnlock()
		r.cacheHits.Add(1)
		return e.ips, nil
	}
	r.mu.RUnlock()

	ips, err := r.upstream.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if len(r.entries) >= r.maxEntries {
		r.evictExpired()
		if len(r.entries) >= r.maxEntries {
			clear(r.entries)
		}
	}
	r.entries[host] = &cacheEntry{
		ips:     ips,
		expires: time.Now().Add(r.maxTTL),
	}
	r.mu.Unlock()

	return ips, nil
}

// evictExpired removes expired entries. Must be called with write lock held.
func (r *CachingResolver) evictExpired() {
	now := time.Now()
	for k, e := range r.entries {
		if now.After(e.expires) {
			delete(r.entries, k)
		}
	}
}

func (r *CachingResolver) CacheHits() int64 {
	return r.cacheHits.Load()
}
