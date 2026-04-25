package secrets

import (
	"context"
	"testing"
)

func TestEnvSourceResolve(t *testing.T) {
	t.Setenv("WARDEN_TEST_SECRET", "hunter2")

	src := NewEnvSource()
	if src.Name() != "env" {
		t.Errorf("name = %q", src.Name())
	}

	val, ok, err := src.Resolve(context.Background(), "WARDEN_TEST_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected found")
	}
	if val != "hunter2" {
		t.Errorf("val = %q", val)
	}
}

func TestEnvSourceNotFound(t *testing.T) {
	src := NewEnvSource()
	_, ok, err := src.Resolve(context.Background(), "WARDEN_NONEXISTENT_VAR_12345")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected not found")
	}
}

func TestEnvSourceEmptyValue(t *testing.T) {
	t.Setenv("WARDEN_EMPTY", "")

	src := NewEnvSource()
	val, ok, err := src.Resolve(context.Background(), "WARDEN_EMPTY")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("empty value should still be found")
	}
	if val != "" {
		t.Errorf("val = %q, want empty", val)
	}
}
