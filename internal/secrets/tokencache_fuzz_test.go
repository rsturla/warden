package secrets

import (
	"testing"
	"time"
)

func FuzzTokenCacheTTL(f *testing.F) {
	f.Add(int64(3600), int64(300))
	f.Add(int64(0), int64(60))
	f.Add(int64(-3600), int64(300))
	f.Add(int64(1), int64(0))

	f.Fuzz(func(t *testing.T, expirySecs int64, marginSecs int64) {
		if marginSecs < 0 {
			marginSecs = 0
		}
		margin := time.Duration(marginSecs) * time.Second

		cache := &tokenCache{
			token:  "tok",
			expiry: time.Now().Add(time.Duration(expirySecs) * time.Second),
			margin: margin,
		}

		ttl := cache.TTL()
		if ttl < 0 {
			t.Error("TTL must not be negative")
		}
	})
}

func FuzzTokenCacheTTLZeroExpiry(f *testing.F) {
	f.Add(int64(60))

	f.Fuzz(func(t *testing.T, marginSecs int64) {
		if marginSecs < 0 {
			marginSecs = 0
		}
		cache := &tokenCache{
			token:  "tok",
			expiry: time.Time{},
			margin: time.Duration(marginSecs) * time.Second,
		}

		if cache.TTL() != 0 {
			t.Error("zero expiry should return 0 TTL")
		}
	})
}
