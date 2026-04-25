package secrets

import (
	"context"
	"os"

	"github.com/rsturla/warden/internal/config"
)

func init() {
	Register("env", func(_ config.SecretConfig) (SecretSource, error) {
		return NewEnvSource(), nil
	})
}

type EnvSource struct{}

func NewEnvSource() *EnvSource { return &EnvSource{} }

func (s *EnvSource) Name() string { return "env" }

func (s *EnvSource) Resolve(_ context.Context, name string) (string, bool, error) {
	val, ok := os.LookupEnv(name)
	return val, ok, nil
}
