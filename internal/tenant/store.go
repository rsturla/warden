package tenant

import (
	"context"
	"errors"
)

var ErrTenantNotFound = errors.New("tenant not found")

type Store interface {
	Get(ctx context.Context, tenantID string) (*Tenant, error)
	List(ctx context.Context) ([]string, error)
	Close() error
}
