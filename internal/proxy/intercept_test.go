package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rsturla/warden/internal/config"
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
