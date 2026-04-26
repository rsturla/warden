package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	wardenca "github.com/rsturla/warden/internal/ca"
	"github.com/rsturla/warden/internal/config"
	wardendns "github.com/rsturla/warden/internal/dns"
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

func TestForwardHTTPIntercept(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for intercepted request")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)

	proxySrv, _, exp := startProxy(t, []config.PolicyRule{
		{Name: "intercept-token", Host: upURL.Hostname(), Path: "/token", Methods: []string{"POST"}, Action: "allow",
			Intercept: &config.InterceptConfig{Credential: "GCP_ACCESS_TOKEN"}},
	}, map[string]string{"GCP_ACCESS_TOKEN": "ya29.test_intercepted"})

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post(upstream.URL+"/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var tokenResp map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if tokenResp["access_token"] != "ya29.test_intercepted" {
		t.Errorf("access_token = %v", tokenResp["access_token"])
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", tokenResp["token_type"])
	}
	if tokenResp["expires_in"] != float64(3600) {
		t.Errorf("expires_in = %v", tokenResp["expires_in"])
	}

	entries := exp.waitForEntries(t, 1)
	if entries[0].Action != "intercept" {
		t.Errorf("action = %q, want intercept", entries[0].Action)
	}
	if len(entries[0].InjectedSecrets) != 1 || entries[0].InjectedSecrets[0] != "GCP_ACCESS_TOKEN" {
		t.Errorf("injected_secrets = %v", entries[0].InjectedSecrets)
	}
}

func TestForwardHTTPInterceptMissingCredential(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)

	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "intercept-missing", Host: upURL.Hostname(), Path: "/token", Action: "allow",
			Intercept: &config.InterceptConfig{Credential: "NONEXISTENT"}},
	}, nil)

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post(upstream.URL+"/token", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestConnectHTTPSIntercept(t *testing.T) {
	upstream, upAddr := startTLSUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for intercepted request")
	}))

	upHost := "oauth2.googleapis.com"

	proxySrv, ca, exp := startProxyWithUpstreamTrust(t, []config.PolicyRule{
		{Name: "intercept-gcp", Host: upHost, Path: "/token", Methods: []string{"POST"}, Action: "allow",
			Intercept: &config.InterceptConfig{Credential: "GCP_ACCESS_TOKEN"}},
	}, map[string]string{"GCP_ACCESS_TOKEN": "ya29.https_intercepted"}, upstream.Certificate())

	_ = upAddr

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

	resp, err := client.Post("https://"+upHost+"/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("HTTPS intercept request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var tokenResp map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if tokenResp["access_token"] != "ya29.https_intercepted" {
		t.Errorf("access_token = %v", tokenResp["access_token"])
	}

	entries := exp.waitForEntries(t, 1)
	if entries[0].Action != "intercept" {
		t.Errorf("action = %q, want intercept", entries[0].Action)
	}
}

func TestBuildTokenResponseDefaultTTL(t *testing.T) {
	body := buildTokenResponse("tok", 0)
	var resp map[string]any
	json.Unmarshal(body, &resp)
	if resp["expires_in"] != float64(3600) {
		t.Errorf("expires_in = %v, want 3600", resp["expires_in"])
	}
	if resp["access_token"] != "tok" {
		t.Errorf("access_token = %v", resp["access_token"])
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", resp["token_type"])
	}
}

func TestBuildTokenResponseWithTTL(t *testing.T) {
	body := buildTokenResponse("tok", 1800*time.Second)
	var resp map[string]any
	json.Unmarshal(body, &resp)
	if resp["expires_in"] != float64(1800) {
		t.Errorf("expires_in = %v, want 1800", resp["expires_in"])
	}
}

func TestBuildTokenResponseShortTTL(t *testing.T) {
	body := buildTokenResponse("tok", 30*time.Second)
	var resp map[string]any
	json.Unmarshal(body, &resp)
	if resp["expires_in"] != float64(30) {
		t.Errorf("expires_in = %v, want 30", resp["expires_in"])
	}
}

func TestCredentialNotFoundError(t *testing.T) {
	err := &credentialNotFoundError{name: "MY_TOKEN"}
	if err.Error() != "credential not found: MY_TOKEN" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestResolveCredentialNotFound(t *testing.T) {
	chain := secrets.NewChain(&stubSource{values: nil})
	p := &Proxy{}
	_, _, err := p.resolveCredential(context.Background(), "MISSING", chain)
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*credentialNotFoundError); !ok {
		t.Errorf("expected credentialNotFoundError, got %T", err)
	}
}

type errorStubSource struct{}

func (s *errorStubSource) Name() string { return "error" }
func (s *errorStubSource) Resolve(_ context.Context, _ string) (string, bool, error) {
	return "", false, fmt.Errorf("source error")
}

func TestResolveCredentialError(t *testing.T) {
	chain := secrets.NewChain(&errorStubSource{})
	p := &Proxy{}
	_, _, err := p.resolveCredential(context.Background(), "KEY", chain)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "source error" {
		t.Errorf("error = %q", err)
	}
}

func TestResolveCredentialFound(t *testing.T) {
	chain := secrets.NewChain(&stubSource{values: map[string]string{"TOK": "val"}})
	p := &Proxy{}
	val, ttl, err := p.resolveCredential(context.Background(), "TOK", chain)
	if err != nil {
		t.Fatal(err)
	}
	if val != "val" {
		t.Errorf("val = %q", val)
	}
	if ttl != 0 {
		t.Errorf("ttl = %v, want 0 for non-expiring source", ttl)
	}
}

type expiringStubSource struct {
	values map[string]string
	ttl    time.Duration
}

func (s *expiringStubSource) Name() string { return "expiring-stub" }
func (s *expiringStubSource) Resolve(_ context.Context, name string) (string, bool, error) {
	v, ok := s.values[name]
	return v, ok, nil
}
func (s *expiringStubSource) TokenTTL() time.Duration { return s.ttl }

func TestResolveCredentialWithTTL(t *testing.T) {
	chain := secrets.NewChain(&expiringStubSource{
		values: map[string]string{"TOK": "val"},
		ttl:    42 * time.Minute,
	})
	p := &Proxy{}
	val, ttl, err := p.resolveCredential(context.Background(), "TOK", chain)
	if err != nil {
		t.Fatal(err)
	}
	if val != "val" {
		t.Errorf("val = %q", val)
	}
	if ttl != 42*time.Minute {
		t.Errorf("ttl = %v, want 42m", ttl)
	}
}

func startProxyWithExpiringSource(t *testing.T, rules []config.PolicyRule, src secrets.SecretSource) *httptest.Server {
	t.Helper()
	ca, err := wardenca.NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewYAMLPolicyEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	chain := secrets.NewChain(src)
	resolver := wardendns.NewStdlibResolver(nil)
	denylist, _ := wardendns.NewDenylist(nil)
	p := New(Config{
		CA:       ca,
		Tenants:  NewSingleTenantResolver(engine, chain),
		Resolver: resolver,
		Denylist: denylist,
	})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv
}

func TestForwardHTTPInterceptWithTTL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)

	proxySrv := startProxyWithExpiringSource(t, []config.PolicyRule{
		{Name: "intercept-ttl", Host: upURL.Hostname(), Path: "/token", Methods: []string{"POST"}, Action: "allow",
			Intercept: &config.InterceptConfig{Credential: "TOK"}},
	}, &expiringStubSource{
		values: map[string]string{"TOK": "ya29.with_ttl"},
		ttl:    1800 * time.Second,
	})

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post(upstream.URL+"/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var tokenResp map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &tokenResp)
	if tokenResp["expires_in"] != float64(1800) {
		t.Errorf("expires_in = %v, want 1800", tokenResp["expires_in"])
	}
}

func TestInterceptNonMatchingPathForwards(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("forwarded"))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)

	proxySrv, _, _ := startProxy(t, []config.PolicyRule{
		{Name: "intercept-token-only", Host: upURL.Hostname(), Path: "/token", Action: "allow",
			Intercept: &config.InterceptConfig{Credential: "TOKEN"}},
		{Name: "allow-rest", Host: upURL.Hostname(), Path: "/**", Action: "allow"},
	}, map[string]string{"TOKEN": "secret"})

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL + "/other-path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "forwarded" {
		t.Errorf("body = %q, expected forwarded", body)
	}
}
