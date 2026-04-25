package secrets

import (
	"context"
	"os"
)

type EnvSource struct{}

func NewEnvSource() *EnvSource { return &EnvSource{} }

func (s *EnvSource) Name() string { return "env" }

func (s *EnvSource) Resolve(_ context.Context, name string) (string, bool, error) {
	val, ok := os.LookupEnv(name)
	return val, ok, nil
}
