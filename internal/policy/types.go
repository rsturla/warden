package policy

import "context"

type RequestContext struct {
	Host   string
	Path   string
	Method string
}

type PolicyDecision struct {
	Allowed  bool
	RuleName string
	Reason   string
	Inject   *InjectionDirective
}

type InjectionDirective struct {
	Headers map[string]string
	Query   map[string]string
}

type PolicyEngine interface {
	Evaluate(ctx context.Context, req *RequestContext) (*PolicyDecision, error)
	// CanMatchHost checks if any allow rule could match this host.
	// Used for early rejection at CONNECT stage before TLS handshake.
	CanMatchHost(host string) bool
}
