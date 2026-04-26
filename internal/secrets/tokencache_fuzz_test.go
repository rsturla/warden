package secrets

import (
	"testing"
	"time"
)

func FuzzTokenCacheTTL(f *testing.F) {
	f.Add(int64(3600), int64(300), false)
	f.Add(int64(0), int64(60), false)
	f.Add(int64(-3600), int64(300), false)
	f.Add(int64(1), int64(0), false)
	f.Add(int64(0), int64(60), true)

	f.Fuzz(func(t *testing.T, expirySecs int64, marginSecs int64, zeroExpiry bool) {
		if marginSecs < 0 {
			marginSecs = 0
		}
		margin := time.Duration(marginSecs) * time.Second

		var expiry time.Time
		if !zeroExpiry {
			expiry = time.Now().Add(time.Duration(expirySecs) * time.Second)
		}

		cache := &tokenCache{
			token:  "tok",
			expiry: expiry,
			margin: margin,
		}

		ttl := cache.TTL()
		if ttl < 0 {
			t.Error("TTL must not be negative")
		}
		if zeroExpiry && ttl != 0 {
			t.Error("zero expiry should return 0 TTL")
		}
	})
}
