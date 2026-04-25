package secrets

import (
	"testing"

	"github.com/rsturla/warden/internal/config"
)

func TestBuildRegisteredType(t *testing.T) {
	src, err := Build(config.SecretConfig{Type: "env"})
	if err != nil {
		t.Fatal(err)
	}
	if src.Name() != "env" {
		t.Errorf("name = %q, want env", src.Name())
	}
}

func TestBuildUnknownType(t *testing.T) {
	_, err := Build(config.SecretConfig{Type: "redis"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestIsRegistered(t *testing.T) {
	for _, name := range []string{"env", "file", "vault", "kubernetes", "github-app"} {
		if !IsRegistered(name) {
			t.Errorf("%q should be registered", name)
		}
	}
	if IsRegistered("redis") {
		t.Error("redis should not be registered")
	}
}
