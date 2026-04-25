package dns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type CachingResolver struct {
	upstream  Resolver
	maxTTL    time.Duration
	mu        sync.RWMutex
	entries   map[string]*cacheEntry
	cacheHits atomic.Int64
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func NewCachingResolver(upstream Resolver, maxTTL time.Duration) *CachingResolver {
	return &CachingResolver{
		upstream: upstream,
		maxTTL:   maxTTL,
		entries:  make(map[string]*cacheEntry),
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
	r.entries[host] = &cacheEntry{
		ips:     ips,
		expires: time.Now().Add(r.maxTTL),
	}
	r.mu.Unlock()

	return ips, nil
}

func (r *CachingResolver) CacheHits() int64 {
	return r.cacheHits.Load()
}
