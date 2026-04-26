package tenant

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

type FileStore struct {
	dir string

	mu      sync.RWMutex
	tenants map[string]*Tenant
	hashes  map[string][32]byte
}

func NewFileStore(dir string) (*FileStore, error) {
	fs := &FileStore{
		dir:     dir,
		tenants: make(map[string]*Tenant),
		hashes:  make(map[string][32]byte),
	}
	if err := fs.loadAll(); err != nil {
		return nil, fmt.Errorf("loading tenants from %s: %w", dir, err)
	}
	return fs, nil
}

func (fs *FileStore) Get(_ context.Context, tenantID string) (*Tenant, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	t, ok := fs.tenants[tenantID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrTenantNotFound, tenantID)
	}
	return t, nil
}

func (fs *FileStore) List(_ context.Context) ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	ids := make([]string, 0, len(fs.tenants))
	for id := range fs.tenants {
		ids = append(ids, id)
	}
	return ids, nil
}

func (fs *FileStore) Close() error {
	return nil
}

func (fs *FileStore) Watch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fs.reload()
		}
	}
}

func (fs *FileStore) loadAll() error {
	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		if err := fs.loadFile(entry.Name()); err != nil {
			return fmt.Errorf("tenant %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func (fs *FileStore) loadFile(filename string) error {
	path := filepath.Join(fs.dir, filename)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	hash := sha256.Sum256(data)
	tenantID := tenantIDFromFilename(filename)

	tc, err := ParseTenantConfig(data)
	if err != nil {
		return err
	}

	t, err := buildTenant(tenantID, tc)
	if err != nil {
		return err
	}

	fs.tenants[tenantID] = t
	fs.hashes[tenantID] = hash
	return nil
}

func (fs *FileStore) reload() {
	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		slog.Error("tenant reload: reading directory", "error", err)
		return
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}

		tenantID := tenantIDFromFilename(entry.Name())
		seen[tenantID] = true

		path := filepath.Join(fs.dir, entry.Name())
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			slog.Error("tenant reload: reading file", "tenant", tenantID, "error", err)
			continue
		}

		hash := sha256.Sum256(data)

		fs.mu.RLock()
		oldHash, exists := fs.hashes[tenantID]
		fs.mu.RUnlock()

		if exists && hash == oldHash {
			continue
		}

		tc, err := ParseTenantConfig(data)
		if err != nil {
			slog.Error("tenant reload: parsing config", "tenant", tenantID, "error", err)
			continue
		}

		t, err := buildTenant(tenantID, tc)
		if err != nil {
			slog.Error("tenant reload: building tenant", "tenant", tenantID, "error", err)
			continue
		}

		fs.mu.Lock()
		fs.tenants[tenantID] = t
		fs.hashes[tenantID] = hash
		fs.mu.Unlock()

		if exists {
			slog.Info("tenant reloaded", "tenant", tenantID)
		} else {
			slog.Info("tenant added", "tenant", tenantID)
		}
	}

	fs.mu.Lock()
	for id := range fs.tenants {
		if !seen[id] {
			delete(fs.tenants, id)
			delete(fs.hashes, id)
			slog.Info("tenant removed", "tenant", id)
		}
	}
	fs.mu.Unlock()
}

func buildTenant(id string, tc *TenantConfig) (*Tenant, error) {
	engine, err := policy.NewEngine(tc.Policies)
	if err != nil {
		return nil, fmt.Errorf("building policy engine: %w", err)
	}

	var sources []secrets.SecretSource
	for _, s := range tc.Secrets {
		src, err := secrets.Build(s)
		if err != nil {
			return nil, fmt.Errorf("building secret source %q: %w", s.Type, err)
		}
		sources = append(sources, src)
	}
	chain := secrets.NewChain(sources...)

	return &Tenant{
		ID:      id,
		Policy:  engine,
		Secrets: chain,
	}, nil
}

func tenantIDFromFilename(filename string) string {
	name := filepath.Base(filename)
	for _, ext := range []string{".yaml", ".yml"} {
		name = strings.TrimSuffix(name, ext)
	}
	return name
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
