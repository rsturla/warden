package tenant

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/rsturla/warden/internal/secrets"
)

const validTenantYAML = `
policies:
  - name: allow-github
    host: "api.github.com"
    path: "/repos/**"
    action: allow
secrets:
  - type: env
`

const anotherTenantYAML = `
policies:
  - name: allow-pypi
    host: "pypi.org"
    action: allow
`

func writeTenantFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileStoreLoadSingle(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	tenant, err := store.Get(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if tenant.ID != "acme" {
		t.Errorf("tenant ID = %q, want %q", tenant.ID, "acme")
	}
	if tenant.Policy == nil {
		t.Error("policy should not be nil")
	}
	if tenant.Secrets == nil {
		t.Error("secrets should not be nil")
	}
}

func TestFileStoreLoadMultiple(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)
	writeTenantFile(t, dir, "beta.yml", anotherTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ids, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("tenant count = %d, want 2", len(ids))
	}

	_, err = store.Get(context.Background(), "acme")
	if err != nil {
		t.Errorf("get acme: %v", err)
	}
	_, err = store.Get(context.Background(), "beta")
	if err != nil {
		t.Errorf("get beta: %v", err)
	}
}

func TestFileStoreNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Get(context.Background(), "nonexistent")
	if !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestFileStoreIgnoresNonYAML(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)
	writeTenantFile(t, dir, "readme.txt", "not a tenant")
	writeTenantFile(t, dir, "notes.md", "also not a tenant")

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ids, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("tenant count = %d, want 1", len(ids))
	}
}

func TestFileStoreIgnoresSubdirectories(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)
	if err := os.Mkdir(filepath.Join(dir, "subdir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ids, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("tenant count = %d, want 1", len(ids))
	}
}

func TestFileStoreInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "bad.yaml", `
policies:
  - host: "example.com"
    action: allow
`)

	_, err := NewFileStore(dir)
	if err == nil {
		t.Fatal("expected error for invalid tenant config")
	}
}

func TestFileStoreInvalidDirectory(t *testing.T) {
	_, err := NewFileStore("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestFileStoreReloadAdd(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ids, _ := store.List(context.Background())
	if len(ids) != 1 {
		t.Fatalf("initial tenant count = %d, want 1", len(ids))
	}

	writeTenantFile(t, dir, "beta.yaml", anotherTenantYAML)
	store.reload()

	ids, _ = store.List(context.Background())
	if len(ids) != 2 {
		t.Errorf("post-reload tenant count = %d, want 2", len(ids))
	}

	_, err = store.Get(context.Background(), "beta")
	if err != nil {
		t.Errorf("get beta after reload: %v", err)
	}
}

func TestFileStoreReloadRemove(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)
	writeTenantFile(t, dir, "beta.yaml", anotherTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	os.Remove(filepath.Join(dir, "beta.yaml"))
	store.reload()

	ids, _ := store.List(context.Background())
	if len(ids) != 1 {
		t.Errorf("post-reload tenant count = %d, want 1", len(ids))
	}

	_, err = store.Get(context.Background(), "beta")
	if !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("expected ErrTenantNotFound after removal, got %v", err)
	}
}

func TestFileStoreReloadUpdate(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	tenantBefore, _ := store.Get(context.Background(), "acme")

	writeTenantFile(t, dir, "acme.yaml", anotherTenantYAML)
	store.reload()

	tenantAfter, _ := store.Get(context.Background(), "acme")

	if tenantBefore.Policy == tenantAfter.Policy {
		t.Error("policy should be different after reload with changed content")
	}
}

func TestFileStoreReloadNoChangeSkips(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	tenantBefore, _ := store.Get(context.Background(), "acme")
	store.reload()
	tenantAfter, _ := store.Get(context.Background(), "acme")

	if tenantBefore != tenantAfter {
		t.Error("unchanged tenant should keep same pointer")
	}
}

func TestFileStoreReloadBadConfigKeepsOld(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	tenantBefore, _ := store.Get(context.Background(), "acme")

	writeTenantFile(t, dir, "acme.yaml", `{{{invalid`)
	store.reload()

	tenantAfter, err := store.Get(context.Background(), "acme")
	if err != nil {
		t.Fatal("bad reload should keep old tenant")
	}
	if tenantBefore != tenantAfter {
		t.Error("failed reload should keep old tenant pointer")
	}
}

func TestFileStoreWatchContext(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "acme.yaml", validTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		store.Watch(ctx, 50*time.Millisecond)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after context cancel")
	}
}

func TestFileStoreYMLExtension(t *testing.T) {
	dir := t.TempDir()
	writeTenantFile(t, dir, "gamma.yml", anotherTenantYAML)

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	tenant, err := store.Get(context.Background(), "gamma")
	if err != nil {
		t.Fatal(err)
	}
	if tenant.ID != "gamma" {
		t.Errorf("tenant ID = %q, want %q", tenant.ID, "gamma")
	}
}

func TestTenantIDFromFilename(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"acme.yaml", "acme"},
		{"acme.yml", "acme"},
		{"my-agent.yaml", "my-agent"},
		{"agent_001.yml", "agent_001"},
		{"corp.dev.yaml", "corp.dev"},
	}
	for _, tt := range tests {
		got := tenantIDFromFilename(tt.filename)
		if got != tt.want {
			t.Errorf("tenantIDFromFilename(%q) = %q, want %q", tt.filename, got, tt.want)
		}
	}
}
