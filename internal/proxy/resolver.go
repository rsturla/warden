package proxy

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
	"github.com/rsturla/warden/internal/tenant"
)

type TenantResolver interface {
	Resolve(r *http.Request) (*resolvedTenant, error)
}

type resolvedTenant struct {
	id      string
	policy  policy.PolicyEngine
	secrets *secrets.Chain
}

type SingleTenantResolver struct {
	tenant *resolvedTenant
}

func NewSingleTenantResolver(pol policy.PolicyEngine, sec *secrets.Chain) *SingleTenantResolver {
	return &SingleTenantResolver{
		tenant: &resolvedTenant{
			policy:  pol,
			secrets: sec,
		},
	}
}

func (r *SingleTenantResolver) Resolve(_ *http.Request) (*resolvedTenant, error) {
	return r.tenant, nil
}

type MTLSTenantResolver struct {
	store tenant.Store
}

func NewMTLSTenantResolver(store tenant.Store) *MTLSTenantResolver {
	return &MTLSTenantResolver{store: store}
}

func (r *MTLSTenantResolver) Resolve(req *http.Request) (*resolvedTenant, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate")
	}
	tenantID := req.TLS.PeerCertificates[0].Subject.CommonName
	t, err := r.store.Get(req.Context(), tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: %w", tenantID, err)
	}
	return &resolvedTenant{
		id:      t.ID,
		policy:  t.Policy,
		secrets: t.Secrets,
	}, nil
}
