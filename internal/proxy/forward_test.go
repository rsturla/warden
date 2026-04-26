package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	wardenca "github.com/rsturla/warden/internal/ca"
	"github.com/rsturla/warden/internal/config"
	wardendns "github.com/rsturla/warden/internal/dns"
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

func startProxyWithDenylist(t *testing.T, rules []config.PolicyRule, secretVals map[string]string, denylist *wardendns.Denylist) *httptest.Server {
	t.Helper()
	ca, _ := wardenca.NewAutoCA("")
	engine, _ := policy.NewYAMLPolicyEngine(rules)
	chain := secrets.NewChain(&stubSource{secretVals})
	resolver := wardendns.NewStdlibResolver(nil)

	p := New(Config{
		CA:        ca,
		Tenants:   NewSingleTenantResolver(engine, chain),
		Resolver:  resolver,
		Denylist:  denylist,
		Telemetry: &collectExporter{},
	})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv
}

func TestForwardUpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "allow", Host: upURL.Hostname(), Path: "/**", Action: "allow"},
	}, nil)

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Errorf("expected 502, got %d", resp.StatusCode)
	}
}

func TestForwardDNSDenylist(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called when IP is denied")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	denylist, _ := wardendns.NewDenylist([]string{"127.0.0.0/8"})

	proxySrv := startProxyWithDenylist(t, []config.PolicyRule{
		{Name: "allow", Host: upURL.Hostname(), Path: "/**", Action: "allow"},
	}, nil, denylist)

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Errorf("expected 502 for denied IP, got %d", resp.StatusCode)
	}
}

func TestForwardSecretResolutionFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called when secret resolution fails")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "inject-missing", Host: upURL.Hostname(), Path: "/**", Action: "allow",
			Inject: &config.InjectConfig{Headers: map[string]string{"Authorization": "Bearer ${NONEXISTENT}"}}},
	}, nil)

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("expected 403 for secret failure, got %d", resp.StatusCode)
	}
}

func TestForwardQueryInjection(t *testing.T) {
	var gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "inject-query", Host: upURL.Hostname(), Path: "/**", Action: "allow",
			Inject: &config.InjectConfig{Query: map[string]string{"api_key": "${KEY}"}}},
	}, map[string]string{"KEY": "secret-key"})

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL + "/data?existing=yes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	q, _ := url.ParseQuery(gotQuery)
	if q.Get("api_key") != "secret-key" {
		t.Errorf("api_key = %q", q.Get("api_key"))
	}
	if q.Get("existing") != "yes" {
		t.Error("existing param lost")
	}
}

func TestForwardMethodDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for denied method")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "get-only", Host: upURL.Hostname(), Path: "/**", Methods: []string{"GET"}, Action: "allow"},
	}, nil)

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post(upstream.URL, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("expected 403 for POST, got %d", resp.StatusCode)
	}
}

func TestForwardPathDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for denied path")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "api-only", Host: upURL.Hostname(), Path: "/api/**", Action: "allow"},
	}, nil)

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL + "/admin/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("expected 403 for wrong path, got %d", resp.StatusCode)
	}
}
