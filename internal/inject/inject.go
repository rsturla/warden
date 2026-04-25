package inject

import (
	"context"
	"net/http"
	"net/url"

	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

type Result struct {
	InjectedSecretNames []string
}

func Apply(ctx context.Context, req *http.Request, directive *policy.InjectionDirective, chain *secrets.Chain) (*Result, error) {
	if directive == nil {
		return nil, nil
	}

	var allNames []string

	for k, tmpl := range directive.Headers {
		resolved, names, err := secrets.ResolveTemplate(ctx, tmpl, chain)
		if err != nil {
			return nil, err
		}
		req.Header.Set(k, resolved)
		allNames = append(allNames, names...)
	}

	if len(directive.Query) > 0 {
		q := req.URL.Query()
		for k, tmpl := range directive.Query {
			resolved, names, err := secrets.ResolveTemplate(ctx, tmpl, chain)
			if err != nil {
				return nil, err
			}
			q.Set(k, resolved)
			allNames = append(allNames, names...)
		}
		req.URL.RawQuery = q.Encode()
	}

	if len(allNames) == 0 {
		return &Result{}, nil
	}
	return &Result{InjectedSecretNames: dedup(allNames)}, nil
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// BuildURL is a helper to construct a URL with injected query params for testing.
func BuildURL(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
