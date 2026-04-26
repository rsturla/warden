package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	wardenca "github.com/rsturla/warden/internal/ca"
	"github.com/rsturla/warden/internal/config"
	wardendns "github.com/rsturla/warden/internal/dns"
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
	"github.com/rsturla/warden/internal/telemetry"
)

func startProxy(t *testing.T, rules []config.PolicyRule, secretVals map[string]string) (*httptest.Server, *wardenca.CA, *collectExporter) {
	t.Helper()
	ca, err := wardenca.NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}

	engine, err := policy.NewYAMLPolicyEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	chain := secrets.NewChain(&stubSource{secretVals})

	resolver := wardendns.NewStdlibResolver(nil)
	denylist, _ := wardendns.NewDenylist(nil)

	exp := &collectExporter{}

	proxy := New(Config{
		CA:        ca,
		Tenants:   NewSingleTenantResolver(engine, chain),
		Resolver:  resolver,
		Denylist:  denylist,
		Telemetry: exp,
	})

	srv := httptest.NewServer(proxy)
	t.Cleanup(srv.Close)
	return srv, ca, exp
}

type stubSource struct {
	values map[string]string
}

func (s *stubSource) Name() string { return "stub" }
func (s *stubSource) Resolve(_ context.Context, name string) (string, bool, error) {
	v, ok := s.values[name]
	return v, ok, nil
}

type collectExporter struct {
	mu      sync.Mutex
	entries []telemetry.RequestLog
}

func (e *collectExporter) LogRequest(_ context.Context, entry telemetry.RequestLog) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entries = append(e.entries, entry)
	return nil
}
func (e *collectExporter) StartSpan(ctx context.Context, _ string, _ ...telemetry.SpanAttr) (context.Context, telemetry.SpanHandle) {
	return ctx, telemetry.NoopSpan{}
}
func (e *collectExporter) RecordMetric(_ context.Context, _ string, _ float64, _ ...telemetry.MetricAttr) {
}
func (e *collectExporter) Close(_ context.Context) error { return nil }
func (e *collectExporter) getEntries() []telemetry.RequestLog {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]telemetry.RequestLog, len(e.entries))
	copy(cp, e.entries)
	return cp
}

func (e *collectExporter) waitForEntries(t *testing.T, n int) []telemetry.RequestLog {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries := e.getEntries()
		if len(entries) >= n {
			return entries
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d log entries, got %d", n, len(entries))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestForwardHTTPAllow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)

	proxySrv, _, exp := startProxy(t, []config.PolicyRule{
		{Name: "allow-upstream", Host: upURL.Hostname(), Path: "/**", Action: "allow"},
	}, nil)

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from upstream" {
		t.Errorf("body = %q", body)
	}

	entries := exp.waitForEntries(t, 1)
	if entries[0].Action != "allow" {
		t.Errorf("action = %q", entries[0].Action)
	}
}

func TestForwardHTTPDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	proxySrv, _, exp := startProxy(t, nil, nil)
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	entries := exp.waitForEntries(t, 1)
	if entries[0].Action != "deny" {
		t.Error("expected deny log entry")
	}
}

func TestForwardHTTPInject(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)

	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "inject", Host: upURL.Hostname(), Path: "/**", Action: "allow",
			Inject: &config.InjectConfig{Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"}}},
	}, map[string]string{"TOKEN": "secret123"})

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer secret123" {
		t.Errorf("auth header = %q", gotAuth)
	}
}

func TestForwardHTTPInjectOverwrite(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)

	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "inject", Host: upURL.Hostname(), Path: "/**", Action: "allow",
			Inject: &config.InjectConfig{Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"}}},
	}, map[string]string{"TOKEN": "real-secret"})

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", upstream.URL, nil)
	req.Header.Set("Authorization", "agent-garbage")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer real-secret" {
		t.Errorf("auth should be overwritten, got %q", gotAuth)
	}
}

func startTLSUpstream(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	upURL, _ := url.Parse(upstream.URL)
	return upstream, upURL.Host
}

func startProxyWithUpstreamTrust(t *testing.T, rules []config.PolicyRule, secretVals map[string]string, upstreamCert *x509.Certificate) (*httptest.Server, *wardenca.CA, *collectExporter) {
	t.Helper()
	ca, err := wardenca.NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}

	engine, err := policy.NewYAMLPolicyEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	chain := secrets.NewChain(&stubSource{secretVals})
	resolver := wardendns.NewStdlibResolver(nil)
	denylist, _ := wardendns.NewDenylist(nil)
	exp := &collectExporter{}

	p := New(Config{
		CA:        ca,
		Tenants:   NewSingleTenantResolver(engine, chain),
		Resolver:  resolver,
		Denylist:  denylist,
		Telemetry: exp,
	})

	if upstreamCert != nil {
		pool := x509.NewCertPool()
		pool.AddCert(upstreamCert)
		p.transport.TLSClientConfig.RootCAs = pool
	}

	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv, ca, exp
}

func TestConnectHTTPSAllow(t *testing.T) {
	var gotPath string
	upstream, upAddr := startTLSUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("secure hello"))
	}))

	upHost, _, _ := net.SplitHostPort(upAddr)

	proxySrv, ca, _ := startProxyWithUpstreamTrust(t, []config.PolicyRule{
		{Name: "allow", Host: upHost, Path: "/**", Action: "allow"},
	}, nil, upstream.Certificate())

	proxyURL, _ := url.Parse(proxySrv.URL)

	pool := x509.NewCertPool()
	pool.AddCert(ca.CACert())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get("https://" + upAddr + "/test-path")
	if err != nil {
		t.Fatalf("HTTPS request through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if string(body) != "secure hello" {
		t.Errorf("body = %q", body)
	}
	if gotPath != "/test-path" {
		t.Errorf("upstream path = %q", gotPath)
	}
}

func TestConnectHTTPSInject(t *testing.T) {
	var gotAuth string
	upstream, upAddr := startTLSUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))

	upHost, _, _ := net.SplitHostPort(upAddr)

	proxySrv, ca, _ := startProxyWithUpstreamTrust(t, []config.PolicyRule{
		{Name: "inject", Host: upHost, Path: "/**", Action: "allow",
			Inject: &config.InjectConfig{Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"}}},
	}, map[string]string{"TOKEN": "https-secret"}, upstream.Certificate())

	proxyURL, _ := url.Parse(proxySrv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(ca.CACert())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get("https://" + upAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer https-secret" {
		t.Errorf("injected auth = %q", gotAuth)
	}
}

func TestConnectHTTPSDeny(t *testing.T) {
	proxySrv, ca, exp := startProxy(t, nil, nil)

	proxyURL, _ := url.Parse(proxySrv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(ca.CACert())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := client.Get("https://denied.example.com/test")
	if err != nil {
		entries := exp.waitForEntries(t, 1)
		if entries[0].Action != "deny" {
			t.Errorf("expected deny, got %q", entries[0].Action)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}
