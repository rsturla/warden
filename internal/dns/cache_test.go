package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type countingResolver struct {
	calls atomic.Int64
	ips   []net.IP
}

func (r *countingResolver) Resolve(_ context.Context, _ string) ([]net.IP, error) {
	r.calls.Add(1)
	return r.ips, nil
}

func TestCachingResolverHit(t *testing.T) {
	upstream := &countingResolver{ips: []net.IP{net.ParseIP("1.2.3.4")}}
	cache := NewCachingResolver(upstream, time.Minute)

	ips1, _ := cache.Resolve(context.Background(), "example.com")
	ips2, _ := cache.Resolve(context.Background(), "example.com")

	if upstream.calls.Load() != 1 {
		t.Errorf("upstream called %d times, want 1", upstream.calls.Load())
	}
	if len(ips1) != 1 || len(ips2) != 1 {
		t.Error("expected IPs from both calls")
	}
	if cache.CacheHits() != 1 {
		t.Errorf("cache hits = %d, want 1", cache.CacheHits())
	}
}

func TestCachingResolverExpiry(t *testing.T) {
	upstream := &countingResolver{ips: []net.IP{net.ParseIP("1.2.3.4")}}
	cache := NewCachingResolver(upstream, time.Millisecond)

	cache.Resolve(context.Background(), "example.com")
	time.Sleep(5 * time.Millisecond)
	cache.Resolve(context.Background(), "example.com")

	if upstream.calls.Load() != 2 {
		t.Errorf("upstream called %d times, want 2 (after expiry)", upstream.calls.Load())
	}
}

func TestCachingResolverDifferentHosts(t *testing.T) {
	upstream := &countingResolver{ips: []net.IP{net.ParseIP("1.2.3.4")}}
	cache := NewCachingResolver(upstream, time.Minute)

	cache.Resolve(context.Background(), "a.com")
	cache.Resolve(context.Background(), "b.com")

	if upstream.calls.Load() != 2 {
		t.Errorf("upstream called %d times, want 2", upstream.calls.Load())
	}
}
