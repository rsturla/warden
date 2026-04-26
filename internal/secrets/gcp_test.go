package secrets

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeTestGCPKey(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	keyJSON, _ := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "test@project.iam.gserviceaccount.com",
		"private_key":  string(pemData),
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	path := t.TempDir() + "/sa-key.json"
	if err := os.WriteFile(path, keyJSON, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGCPServiceAccountSourceKeyExchange(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("assertion") == "" {
			t.Error("missing assertion")
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.test_token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	keyPath := writeTestGCPKey(t, key)

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: keyPath,
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
	if val != "ya29.test_token" {
		t.Errorf("got %q", val)
	}

	// Second call should use cache
	val2, ok2, err := src.Resolve(ctx, "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok2 || val2 != "ya29.test_token" {
		t.Error("cached value mismatch")
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 HTTP call, got %d", calls.Load())
	}
}

func TestGCPServiceAccountSourceMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("missing Metadata-Flavor header")
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.metadata_token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		TokenURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	val, ok, err := src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok")
	}
	if val != "ya29.metadata_token" {
		t.Errorf("got %q", val)
	}
}

func TestGCPServiceAccountSourceWrongName(t *testing.T) {
	src := &GCPServiceAccountSource{
		cache: newTokenCache(5 * time.Minute),
	}

	_, ok, err := src.Resolve(context.Background(), "SOMETHING_ELSE")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found for non-GCP_ACCESS_TOKEN")
	}
}

func TestGCPServiceAccountSourceName(t *testing.T) {
	src := &GCPServiceAccountSource{}
	if src.Name() != "gcp-service-account" {
		t.Errorf("Name() = %q", src.Name())
	}
}

func TestGCPServiceAccountSourceConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.concurrent",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		TokenURL: srv.URL,
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

func TestGCPServiceAccountSourceTokenRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.refreshed",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	keyPath := writeTestGCPKey(t, key)

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: keyPath,
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Force expired token
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

func TestGCPServiceAccountSourceServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		TokenURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPServiceAccountSourceCustomScopes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.scoped",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	keyPath := writeTestGCPKey(t, key)

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: keyPath,
		Scopes: []string{
			"https://www.googleapis.com/auth/compute.readonly",
			"https://www.googleapis.com/auth/devstorage.read_only",
		},
		TokenURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	if src.scopes != "https://www.googleapis.com/auth/compute.readonly https://www.googleapis.com/auth/devstorage.read_only" {
		t.Errorf("scopes = %q", src.scopes)
	}

	val, ok, err := src.Resolve(context.Background(), "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "ya29.scoped" {
		t.Errorf("got %q/%v", val, ok)
	}
}

func TestGCPServiceAccountSourceBadCredentialsFile(t *testing.T) {
	_, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: "/nonexistent/sa-key.json",
	})
	if err == nil {
		t.Fatal("expected error for missing credentials file")
	}
}

func TestGCPServiceAccountSourceBadJSON(t *testing.T) {
	path := t.TempDir() + "/bad.json"
	os.WriteFile(path, []byte("not json"), 0600)

	_, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: path,
	})
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestGCPServiceAccountSourceWrongType(t *testing.T) {
	keyJSON, _ := json.Marshal(map[string]string{
		"type": "authorized_user",
	})
	path := t.TempDir() + "/wrong-type.json"
	os.WriteFile(path, keyJSON, 0600)

	_, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: path,
	})
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestGCPServiceAccountSourceCustomTokenName(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.vertex_token",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	keyPath := writeTestGCPKey(t, key)

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: keyPath,
		TokenName:       "GCP_VERTEX_TOKEN",
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Should respond to custom name
	val, ok, err := src.Resolve(ctx, "GCP_VERTEX_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "ya29.vertex_token" {
		t.Errorf("got %q/%v", val, ok)
	}

	// Should NOT respond to default name
	_, ok, err = src.Resolve(ctx, "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("should not respond to default name when custom name set")
	}
}

func TestGCPServiceAccountSourceDefaultScope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keyPath := writeTestGCPKey(t, key)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.default_scope",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: keyPath,
		TokenURL:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	if src.scopes != gcpDefaultScope {
		t.Errorf("scopes = %q, want %q", src.scopes, gcpDefaultScope)
	}
}
