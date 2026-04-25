package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func setupFileSource(t *testing.T, files map[string]string) *FileSource {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src, err := NewFileSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	return src
}

func TestFileSourceResolve(t *testing.T) {
	src := setupFileSource(t, map[string]string{
		"API_KEY": "secret123",
	})

	if src.Name() != "file" {
		t.Errorf("name = %q", src.Name())
	}

	val, ok, err := src.Resolve(context.Background(), "API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if val != "secret123" {
		t.Errorf("val = %q", val)
	}
}

func TestFileSourceNotFound(t *testing.T) {
	src := setupFileSource(t, map[string]string{})

	_, ok, err := src.Resolve(context.Background(), "MISSING")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found")
	}
}

func TestFileSourceTrimWhitespace(t *testing.T) {
	src := setupFileSource(t, map[string]string{
		"TOKEN": "  abc123  \n",
	})

	val, ok, err := src.Resolve(context.Background(), "TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if val != "abc123" {
		t.Errorf("val = %q, want %q", val, "abc123")
	}
}

func TestFileSourceEmptyFile(t *testing.T) {
	src := setupFileSource(t, map[string]string{
		"EMPTY": "",
	})

	val, ok, err := src.Resolve(context.Background(), "EMPTY")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if val != "" {
		t.Errorf("val = %q, want empty", val)
	}
}

func TestFileSourcePathTraversal(t *testing.T) {
	src := setupFileSource(t, map[string]string{
		"LEGIT": "ok",
	})

	traversals := []string{
		"../etc/passwd",
		"../../etc/shadow",
	}
	for _, name := range traversals {
		_, _, err := src.Resolve(context.Background(), name)
		if err == nil {
			t.Errorf("expected error for path traversal %q", name)
		}
	}
}

func TestFileSourceInvalidDir(t *testing.T) {
	_, err := NewFileSource("/nonexistent/path/12345")
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}
