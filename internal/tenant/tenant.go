package tenant

import (
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

type Tenant struct {
	ID      string
	Policy  policy.PolicyEngine
	Secrets *secrets.Chain
}
