package proxy

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzBuildTokenResponse(f *testing.F) {
	f.Add("ya29.abc123", int64(3600))
	f.Add("", int64(0))
	f.Add("tok-with-special-chars!@#$%^&*()", int64(300))
	f.Add("a]b\"c\\d", int64(-1))
	f.Add("x", int64(86400))

	f.Fuzz(func(t *testing.T, token string, ttlSecs int64) {
		ttl := time.Duration(ttlSecs) * time.Second
		body := buildTokenResponse(token, ttl)

		var resp map[string]any
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		if _, ok := resp["access_token"]; !ok {
			t.Fatal("missing access_token")
		}
		if resp["token_type"] != "Bearer" {
			t.Errorf("token_type = %v", resp["token_type"])
		}
		expiresIn, ok := resp["expires_in"].(float64)
		if !ok {
			t.Fatal("expires_in not a number")
		}
		if ttl > 0 {
			if int(expiresIn) != int(ttl.Seconds()) {
				t.Errorf("expires_in = %v, want %v", expiresIn, ttl.Seconds())
			}
		} else {
			if int(expiresIn) != 3600 {
				t.Errorf("expires_in = %v, want 3600 for non-positive TTL", expiresIn)
			}
		}
	})
}
