package secrets

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubAppSourceCreateJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	src := &GitHubAppSource{
		appID:          12345,
		installationID: 67890,
		key:            key,
		client:         &http.Client{},
		apiBase:        "https://api.github.com",
		cache:          newTokenCache(5 * time.Minute),
	}

	jwt, err := src.createJWT()
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]string
	json.Unmarshal(headerBytes, &header)
	if header["alg"] != "RS256" {
		t.Errorf("alg = %q", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("typ = %q", header["typ"])
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	json.Unmarshal(claimsBytes, &claims)
	if int64(claims["iss"].(float64)) != 12345 {
		t.Errorf("iss = %v", claims["iss"])
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))
	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], sigBytes)
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestGitHubAppSourceTokenExchange(t *testing.T) {
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Error("missing Bearer auth")
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_testtoken123",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	src := &GitHubAppSource{
		appID:          12345,
		installationID: 67890,
		key:            key,
		client:         &http.Client{},
		apiBase:        srv.URL,
		cache:          newTokenCache(5 * time.Minute),
	}

	ctx := context.Background()

	val, ok, err := src.Resolve(ctx, "GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok")
	}
	if val != "ghs_testtoken123" {
		t.Errorf("got %q", val)
	}

	// Second call should use cache
	val2, ok2, err := src.Resolve(ctx, "GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok2 || val2 != "ghs_testtoken123" {
		t.Error("cached value mismatch")
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 HTTP call, got %d", calls.Load())
	}

	// Non-GITHUB_TOKEN should return not found
	_, ok3, err := src.Resolve(ctx, "OTHER_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if ok3 {
		t.Error("expected not found for non-GITHUB_TOKEN")
	}
}

func TestGitHubAppSourceConcurrent(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_concurrent",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	src := &GitHubAppSource{
		appID:          1,
		installationID: 1,
		key:            key,
		client:         &http.Client{},
		apiBase:        srv.URL,
		cache:          newTokenCache(5 * time.Minute),
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, ok, err := src.Resolve(ctx, "GITHUB_TOKEN")
			if err != nil {
				t.Errorf("concurrent resolve: %v", err)
				return
			}
			if !ok || val != "ghs_concurrent" {
				t.Errorf("concurrent value = %q/%v", val, ok)
			}
		}()
	}
	wg.Wait()
}

func TestGitHubAppSourceTokenRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_refreshed",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	src := &GitHubAppSource{
		appID:          1,
		installationID: 1,
		key:            key,
		client:         &http.Client{},
		apiBase:        srv.URL,
		cache: &tokenCache{
			token:  "old_token",
			expiry: time.Now().Add(-1 * time.Hour),
			margin: 5 * time.Minute,
		},
	}

	val, _, err := src.Resolve(context.Background(), "GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if val == "old_token" {
		t.Error("should have refreshed")
	}
	if val != "ghs_refreshed" {
		t.Errorf("got %q", val)
	}
}

func TestGitHubAppSourceName(t *testing.T) {
	src := &GitHubAppSource{}
	if src.Name() != "github-app" {
		t.Errorf("Name() = %q", src.Name())
	}
}

func TestNewGitHubAppSource(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	path := t.TempDir() + "/key.pem"
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	src, err := NewGitHubAppSource(GitHubAppConfig{
		AppID:          1,
		InstallationID: 2,
		PrivateKeyPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.apiBase != "https://api.github.com" {
		t.Errorf("default apiBase = %q", src.apiBase)
	}
}

func TestNewGitHubAppSourceBadKey(t *testing.T) {
	path := t.TempDir() + "/bad.pem"
	os.WriteFile(path, []byte("not a key"), 0600)

	_, err := NewGitHubAppSource(GitHubAppConfig{
		AppID:          1,
		InstallationID: 2,
		PrivateKeyPath: path,
	})
	if err == nil {
		t.Fatal("expected error for bad key")
	}
}

func TestNewGitHubAppSourceMissingKey(t *testing.T) {
	_, err := NewGitHubAppSource(GitHubAppConfig{
		AppID:          1,
		InstallationID: 2,
		PrivateKeyPath: "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}
