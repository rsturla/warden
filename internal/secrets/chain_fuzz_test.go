package secrets

import (
	"context"
	"testing"
	"time"
)

func FuzzResolveWithTTL(f *testing.F) {
	f.Add("TOKEN", "value", int64(3600), true)
	f.Add("MISSING", "", int64(0), false)
	f.Add("KEY", "val", int64(-1), true)
	f.Add("", "", int64(0), false)

	f.Fuzz(func(t *testing.T, name, value string, ttlSecs int64, expiring bool) {
		var src SecretSource
		if expiring {
			src = &expiringStubSource{
				stubSource: stubSource{"stub", map[string]string{name: value}},
				ttl:        time.Duration(ttlSecs) * time.Second,
			}
		} else {
			src = &stubSource{"stub", map[string]string{name: value}}
		}

		chain := NewChain(src)

		val, ttl, ok, err := chain.ResolveWithTTL(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}

		if name != "" {
			if !ok {
				t.Fatal("expected found")
			}
			if val != value {
				t.Errorf("value mismatch")
			}
			if expiring && ttl != time.Duration(ttlSecs)*time.Second {
				t.Errorf("TTL mismatch")
			}
			if !expiring && ttl != 0 {
				t.Errorf("non-expiring source should return 0 TTL")
			}
		}
	})
}
