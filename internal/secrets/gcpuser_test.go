package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeTestADC(t *testing.T) string {
	t.Helper()
	credJSON, _ := json.Marshal(map[string]string{
		"type":          "authorized_user",
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		"refresh_token": "test-refresh-token",
	})
	path := t.TempDir() + "/adc.json"
	if err := os.WriteFile(path, credJSON, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGCPAuthorizedUserSourceTokenExchange(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_id") != "test-client-id" {
			t.Errorf("client_id = %q", r.Form.Get("client_id"))
		}
		if r.Form.Get("client_secret") != "test-client-secret" {
			t.Errorf("client_secret = %q", r.Form.Get("client_secret"))
		}
		if r.Form.Get("refresh_token") != "test-refresh-token" {
			t.Errorf("refresh_token = %q", r.Form.Get("refresh_token"))
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.user_token",
			"expires_in":   3599,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: writeTestADC(t),
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	val, ok, err := src.Resolve(ctx, "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok")
	}
	if val != "ya29.user_token" {
		t.Errorf("got %q", val)
	}

	// Second call should use cache
	val2, ok2, err := src.Resolve(ctx, "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok2 || val2 != "ya29.user_token" {
		t.Error("cached value mismatch")
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 HTTP call, got %d", calls.Load())
	}
}

func TestGCPAuthorizedUserSourceWrongName(t *testing.T) {
	src := &GCPAuthorizedUserSource{
		cache:     newTokenCache(5 * time.Minute),
		tokenName: "GCP_ACCESS_TOKEN",
	}

	_, ok, err := src.Resolve(context.Background(), "OTHER")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found")
	}
}

func TestGCPAuthorizedUserSourceName(t *testing.T) {
	src := &GCPAuthorizedUserSource{}
	if src.Name() != "gcp-authorized-user" {
		t.Errorf("Name() = %q", src.Name())
	}
}

func TestGCPAuthorizedUserSourceCustomTokenName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.custom",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: writeTestADC(t),
		TokenName:       "MY_TOKEN",
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	val, ok, err := src.Resolve(context.Background(), "MY_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "ya29.custom" {
		t.Errorf("got %q/%v", val, ok)
	}

	_, ok, _ = src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if ok {
		t.Error("should not respond to default name")
	}
}

func TestGCPAuthorizedUserSourceConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.concurrent",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: writeTestADC(t),
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, ok, err := src.Resolve(ctx, "GCP_ACCESS_TOKEN")
			if err != nil {
				t.Errorf("concurrent resolve: %v", err)
				return
			}
			if !ok || val != "ya29.concurrent" {
				t.Errorf("concurrent value = %q/%v", val, ok)
			}
		}()
	}
	wg.Wait()
}

func TestGCPAuthorizedUserSourceTokenRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.refreshed",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: writeTestADC(t),
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	src.cache.token = "old_token"
	src.cache.expiry = time.Now().Add(-1 * time.Hour)

	val, _, err := src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if val == "old_token" {
		t.Error("should have refreshed")
	}
	if val != "ya29.refreshed" {
		t.Errorf("got %q", val)
	}
}

func TestGCPAuthorizedUserSourceServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: writeTestADC(t),
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPAuthorizedUserSourceMissingFields(t *testing.T) {
	tests := []struct {
		name string
		cred map[string]string
	}{
		{"missing client_id", map[string]string{
			"type": "authorized_user", "client_secret": "s", "refresh_token": "r",
		}},
		{"missing client_secret", map[string]string{
			"type": "authorized_user", "client_id": "c", "refresh_token": "r",
		}},
		{"missing refresh_token", map[string]string{
			"type": "authorized_user", "client_id": "c", "client_secret": "s",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credJSON, _ := json.Marshal(tt.cred)
			path := t.TempDir() + "/bad.json"
			os.WriteFile(path, credJSON, 0600)

			_, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
				CredentialsFile: path,
			})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestGCPAuthorizedUserSourceWrongType(t *testing.T) {
	credJSON, _ := json.Marshal(map[string]string{
		"type": "service_account",
	})
	path := t.TempDir() + "/wrong.json"
	os.WriteFile(path, credJSON, 0600)

	_, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: path,
	})
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestGCPAuthorizedUserSourceTokenTTL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.ttl_user",
			"expires_in":   1800,
		})
	}))
	defer srv.Close()

	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: writeTestADC(t),
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}

	ttl := src.TokenTTL()
	if ttl < 25*time.Minute || ttl > 31*time.Minute {
		t.Errorf("TTL = %v, want ~30m", ttl)
	}
}

func TestGCPAuthorizedUserSourceTokenTTLBeforeResolve(t *testing.T) {
	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: writeTestADC(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.TokenTTL() != 0 {
		t.Errorf("TTL before resolve = %v, want 0", src.TokenTTL())
	}
}

func TestGCPAuthorizedUserSourceRequiresCredentialsFile(t *testing.T) {
	_, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{})
	if err == nil {
		t.Fatal("expected error when no credentials_file")
	}
}

func TestGCPAuthorizedUserSourceCustomTokenURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.custom_uri",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	credJSON, _ := json.Marshal(map[string]string{
		"type":          "authorized_user",
		"client_id":     "cid",
		"client_secret": "csec",
		"refresh_token": "rtok",
		"token_uri":     srv.URL,
	})
	path := t.TempDir() + "/custom-uri.json"
	os.WriteFile(path, credJSON, 0600)

	src, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: path,
	})
	if err != nil {
		t.Fatal(err)
	}

	val, ok, err := src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "ya29.custom_uri" {
		t.Errorf("got %q/%v", val, ok)
	}
}

func TestGCPAuthorizedUserSourceBadFile(t *testing.T) {
	_, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: "/nonexistent/adc.json",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPAuthorizedUserSourceBadJSON(t *testing.T) {
	path := t.TempDir() + "/bad.json"
	os.WriteFile(path, []byte("not json"), 0600)

	_, err := NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
		CredentialsFile: path,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
