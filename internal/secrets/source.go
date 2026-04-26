package secrets

import (
	"context"
	"time"
)

type SecretSource interface {
	Name() string
	Resolve(ctx context.Context, name string) (string, bool, error)
}

type ExpiringSource interface {
	SecretSource
	TokenTTL() time.Duration
}
