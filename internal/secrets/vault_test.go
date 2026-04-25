package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultSourceResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		switch r.URL.Path {
		case "/v1/secret/data/myapp/db":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"password": "s3cret",
						"username": "admin",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "test-token")

	src, err := NewVaultSource(VaultConfig{
		Address: srv.URL,
		Mount:   "secret",
		Auth:    "token",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	val, ok, err := src.Resolve(ctx, "myapp/db/password")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok")
	}
	if val != "s3cret" {
		t.Errorf("got %q, want %q", val, "s3cret")
	}

	val, ok, err = src.Resolve(ctx, "myapp/db/username")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "admin" {
		t.Errorf("got %q/%v, want admin/true", val, ok)
	}

	_, ok, err = src.Resolve(ctx, "myapp/db/missing-key")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found for missing key")
	}

	_, ok, err = src.Resolve(ctx, "nonexistent/path/key")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found for missing path")
	}
}

func TestVaultSourceForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("permission denied"))
	}))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "bad-token")

	src, err := NewVaultSource(VaultConfig{
		Address: srv.URL,
		Mount:   "secret",
		Auth:    "token",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = src.Resolve(context.Background(), "any/key")
	if err == nil {
		t.Fatal("expected error for forbidden")
	}
}

func TestVaultSourceMissingToken(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "")

	src, err := NewVaultSource(VaultConfig{
		Address: "http://localhost:8200",
		Mount:   "secret",
		Auth:    "token",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = src.Resolve(context.Background(), "any/key")
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestVaultSourceName(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "x")
	src, err := NewVaultSource(VaultConfig{Address: "http://x", Mount: "s", Auth: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if src.Name() != "vault" {
		t.Errorf("Name() = %q", src.Name())
	}
}

func TestVaultSourcePrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/data/warden/myapp/db" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{"pw": "val"},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "t")

	src, err := NewVaultSource(VaultConfig{
		Address: srv.URL,
		Mount:   "kv",
		Prefix:  "warden/",
		Auth:    "token",
	})
	if err != nil {
		t.Fatal(err)
	}

	val, ok, err := src.Resolve(context.Background(), "myapp/db/pw")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "val" {
		t.Errorf("got %q/%v", val, ok)
	}
}

func TestSplitVaultName(t *testing.T) {
	tests := []struct {
		name     string
		wantPath string
		wantKey  string
	}{
		{"myapp/db/password", "myapp/db", "password"},
		{"simple", "simple", "simple"},
		{"a/b", "a", "b"},
	}
	for _, tt := range tests {
		path, key := splitVaultName(tt.name)
		if path != tt.wantPath || key != tt.wantKey {
			t.Errorf("splitVaultName(%q) = (%q, %q), want (%q, %q)",
				tt.name, path, key, tt.wantPath, tt.wantKey)
		}
	}
}
