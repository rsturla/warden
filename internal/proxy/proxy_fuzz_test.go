package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	wardenca "github.com/rsturla/warden/internal/ca"
	wardendns "github.com/rsturla/warden/internal/dns"
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

func FuzzProxyRequest(f *testing.F) {
	f.Add("GET", "/api/v1/users", "api.github.com")
	f.Add("POST", "/repos/myorg/app/pulls", "api.github.com")
	f.Add("DELETE", "/", "evil.com")
	f.Add("GET", "/../../../etc/passwd", "localhost")

	ca, _ := wardenca.NewAutoCA("")
	engine, _ := policy.NewYAMLPolicyEngine(nil)
	chain := secrets.NewChain()
	resolver := wardendns.NewStdlibResolver(nil)
	denylist, _ := wardendns.NewDenylist(nil)

	p := New(Config{
		CA:       ca,
		Tenants:  NewSingleTenantResolver(engine, chain),
		Resolver: resolver,
		Denylist: denylist,
	})

	f.Fuzz(func(t *testing.T, method, path, host string) {
		req, err := http.NewRequest(method, "http://"+host+path, nil)
		if err != nil {
			return
		}
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
	})
}
