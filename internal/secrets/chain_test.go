package secrets

import (
	"context"
	"fmt"
	"testing"
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
