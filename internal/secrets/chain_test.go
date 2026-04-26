package secrets

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type stubSource struct {
	name   string
	values map[string]string
}

func (s *stubSource) Name() string { return s.name }
func (s *stubSource) Resolve(_ context.Context, name string) (string, bool, error) {
	v, ok := s.values[name]
	return v, ok, nil
}

type errorSource struct{}

func (s *errorSource) Name() string { return "error" }
func (s *errorSource) Resolve(_ context.Context, _ string) (string, bool, error) {
	return "", false, fmt.Errorf("source error")
}

func TestChainFirstMatchWins(t *testing.T) {
	chain := NewChain(
		&stubSource{"first", map[string]string{"KEY": "from-first"}},
		&stubSource{"second", map[string]string{"KEY": "from-second"}},
	)

	val, ok, err := chain.Resolve(context.Background(), "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if val != "from-first" {
		t.Errorf("val = %q, want from-first", val)
	}
}

func TestChainFallthrough(t *testing.T) {
	chain := NewChain(
		&stubSource{"first", map[string]string{}},
		&stubSource{"second", map[string]string{"KEY": "from-second"}},
	)

	val, ok, err := chain.Resolve(context.Background(), "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if val != "from-second" {
		t.Errorf("val = %q", val)
	}
}

func TestChainNotFound(t *testing.T) {
	chain := NewChain(
		&stubSource{"a", map[string]string{}},
		&stubSource{"b", map[string]string{}},
	)

	_, ok, err := chain.Resolve(context.Background(), "MISSING")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found")
	}
}

func TestChainEmpty(t *testing.T) {
	chain := NewChain()
	_, ok, err := chain.Resolve(context.Background(), "ANY")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("empty chain should never find")
	}
}

func TestChainErrorPropagates(t *testing.T) {
	chain := NewChain(&errorSource{})
	_, _, err := chain.Resolve(context.Background(), "KEY")
	if err == nil {
		t.Error("expected error")
	}
}

type expiringStubSource struct {
	stubSource
	ttl time.Duration
}

func (s *expiringStubSource) TokenTTL() time.Duration { return s.ttl }

func TestResolveWithTTLFromExpiringSource(t *testing.T) {
	chain := NewChain(&expiringStubSource{
		stubSource: stubSource{"gcp", map[string]string{"TOKEN": "val"}},
		ttl:        42 * time.Minute,
	})
	val, ttl, ok, err := chain.ResolveWithTTL(context.Background(), "TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "val" {
		t.Errorf("got %q/%v", val, ok)
	}
	if ttl != 42*time.Minute {
		t.Errorf("ttl = %v, want 42m", ttl)
	}
}

func TestResolveWithTTLFromPlainSource(t *testing.T) {
	chain := NewChain(&stubSource{"env", map[string]string{"KEY": "val"}})
	_, ttl, ok, err := chain.ResolveWithTTL(context.Background(), "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if ttl != 0 {
		t.Errorf("ttl = %v, want 0 for non-expiring source", ttl)
	}
}

func TestResolveWithTTLNotFound(t *testing.T) {
	chain := NewChain(&stubSource{"a", map[string]string{}})
	_, _, ok, err := chain.ResolveWithTTL(context.Background(), "MISSING")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found")
	}
}

func TestResolveWithTTLErrorPropagates(t *testing.T) {
	chain := NewChain(&errorSource{})
	_, _, _, err := chain.ResolveWithTTL(context.Background(), "KEY")
	if err == nil {
		t.Error("expected error")
	}
}

func TestResolveWithTTLFallthrough(t *testing.T) {
	chain := NewChain(
		&stubSource{"empty", map[string]string{}},
		&expiringStubSource{
			stubSource: stubSource{"gcp", map[string]string{"TOK": "val"}},
			ttl:        10 * time.Minute,
		},
	)
	val, ttl, ok, err := chain.ResolveWithTTL(context.Background(), "TOK")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || val != "val" {
		t.Errorf("got %q/%v", val, ok)
	}
	if ttl != 10*time.Minute {
		t.Errorf("ttl = %v, want 10m", ttl)
	}
}

func TestResolveWithTTLEmpty(t *testing.T) {
	chain := NewChain()
	_, _, ok, err := chain.ResolveWithTTL(context.Background(), "ANY")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("empty chain should never find")
	}
}
