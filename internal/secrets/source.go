package secrets

import "context"

type SecretSource interface {
	Name() string
	Resolve(ctx context.Context, name string) (string, bool, error)
}
