package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
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
	"github.com/rsturla/warden/internal/tenant"
)

type memoryStore struct {
	tenants map[string]*tenant.Tenant
}

func (s *memoryStore) Get(_ context.Context, id string) (*tenant.Tenant, error) {
	t, ok := s.tenants[id]
	if !ok {
		return nil, tenant.ErrTenantNotFound
	}
	return t, nil
}

func (s *memoryStore) List(_ context.Context) ([]string, error) {
	ids := make([]string, 0, len(s.tenants))
	for id := range s.tenants {
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *memoryStore) Close() error { return nil }

type testPKI struct {
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	caCertPEM  []byte
	serverCert tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Tenant CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "warden-proxy"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	serverCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}

	return &testPKI{
		caKey:      caKey,
		caCert:     caCert,
		caCertPEM:  caCertPEM,
		serverCert: serverCert,
	}
}

func (pki *testPKI) clientCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, pki.caCert, &key.PublicKey, pki.caKey)
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func startMTLSProxy(t *testing.T, pki *testPKI, store tenant.Store) (string, *wardenca.CA, *collectExporter) {
	t.Helper()
	mitmCA, _ := wardenca.NewAutoCA("")
	resolver := wardendns.NewStdlibResolver(nil)
	denylist, _ := wardendns.NewDenylist(nil)
	exp := &collectExporter{}

	p := New(Config{
		CA:        mitmCA,
		Tenants:   NewMTLSTenantResolver(store),
		Resolver:  resolver,
		Denylist:  denylist,
		Telemetry: exp,
	})

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(pki.caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, tlsConfig)

	srv := &http.Server{Handler: p}
	go srv.Serve(tlsLn)
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String(), mitmCA, exp
}

func dialProxy(t *testing.T, addr string, pki *testPKI, clientCert tls.Certificate) *tls.Conn {
	t.Helper()
	serverCAPool := x509.NewCertPool()
	serverCAPool.AddCert(pki.caCert)

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverCAPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func sendHTTPViaProxy(t *testing.T, conn net.Conn, method, fullURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.WriteProxy(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestMultiTenantForwardAllow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	pki := newTestPKI(t)

	upURL, _ := url.Parse(upstream.URL)

	engineAlpha, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
		{Name: "allow", Host: upURL.Hostname(), Path: "/**", Action: "allow"},
	})

	store := &memoryStore{tenants: map[string]*tenant.Tenant{
		"alpha": {ID: "alpha", Policy: engineAlpha, Secrets: secrets.NewChain()},
	}}

	addr, _, exp := startMTLSProxy(t, pki, store)

	conn := dialProxy(t, addr, pki, pki.clientCert(t, "alpha"))
	defer conn.Close()

	resp := sendHTTPViaProxy(t, conn, "GET", upstream.URL+"/test")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q", body)
	}

	entries := exp.getEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	if entries[0].TenantID != "alpha" {
		t.Errorf("tenant_id = %q, want %q", entries[0].TenantID, "alpha")
	}
	if entries[0].Action != "allow" {
		t.Errorf("action = %q", entries[0].Action)
	}
}

func TestMultiTenantForwardDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)

	pki := newTestPKI(t)

	engineBeta, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
		{Name: "deny-all", Host: upURL.Hostname(), Path: "/**", Action: "deny"},
	})

	store := &memoryStore{tenants: map[string]*tenant.Tenant{
		"beta": {ID: "beta", Policy: engineBeta, Secrets: secrets.NewChain()},
	}}

	addr, _, exp := startMTLSProxy(t, pki, store)

	conn := dialProxy(t, addr, pki, pki.clientCert(t, "beta"))
	defer conn.Close()

	resp := sendHTTPViaProxy(t, conn, "GET", upstream.URL+"/test")
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}

	entries := exp.getEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	if entries[0].TenantID != "beta" {
		t.Errorf("tenant_id = %q, want %q", entries[0].TenantID, "beta")
	}
}

func TestMultiTenantUnknownTenant(t *testing.T) {
	pki := newTestPKI(t)
	store := &memoryStore{tenants: map[string]*tenant.Tenant{}}

	addr, _, _ := startMTLSProxy(t, pki, store)

	conn := dialProxy(t, addr, pki, pki.clientCert(t, "unknown-agent"))
	defer conn.Close()

	resp := sendHTTPViaProxy(t, conn, "GET", "http://example.com/test")
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMultiTenantIsolation(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)

	pki := newTestPKI(t)

	makeEngine := func() policy.PolicyEngine {
		e, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
			{Name: "allow", Host: upURL.Hostname(), Path: "/**", Action: "allow",
				Inject: &config.InjectConfig{Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"}}},
		})
		return e
	}

	store := &memoryStore{tenants: map[string]*tenant.Tenant{
		"alpha": {ID: "alpha", Policy: makeEngine(), Secrets: secrets.NewChain(&stubSource{values: map[string]string{"TOKEN": "alpha-secret"}})},
		"beta":  {ID: "beta", Policy: makeEngine(), Secrets: secrets.NewChain(&stubSource{values: map[string]string{"TOKEN": "beta-secret"}})},
	}}

	addr, _, _ := startMTLSProxy(t, pki, store)

	connAlpha := dialProxy(t, addr, pki, pki.clientCert(t, "alpha"))
	defer connAlpha.Close()
	resp := sendHTTPViaProxy(t, connAlpha, "GET", upstream.URL)
	resp.Body.Close()
	if gotAuth != "Bearer alpha-secret" {
		t.Errorf("alpha auth = %q, want %q", gotAuth, "Bearer alpha-secret")
	}

	connBeta := dialProxy(t, addr, pki, pki.clientCert(t, "beta"))
	defer connBeta.Close()
	resp = sendHTTPViaProxy(t, connBeta, "GET", upstream.URL)
	resp.Body.Close()
	if gotAuth != "Bearer beta-secret" {
		t.Errorf("beta auth = %q, want %q", gotAuth, "Bearer beta-secret")
	}
}

func TestMultiTenantPolicyIsolation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)

	pki := newTestPKI(t)

	engineAlpha, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
		{Name: "api-only", Host: upURL.Hostname(), Path: "/api/**", Action: "allow"},
	})
	engineBeta, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
		{Name: "data-only", Host: upURL.Hostname(), Path: "/data/**", Action: "allow"},
	})

	store := &memoryStore{tenants: map[string]*tenant.Tenant{
		"alpha": {ID: "alpha", Policy: engineAlpha, Secrets: secrets.NewChain()},
		"beta":  {ID: "beta", Policy: engineBeta, Secrets: secrets.NewChain()},
	}}

	addr, _, _ := startMTLSProxy(t, pki, store)

	// Alpha can access /api but not /data
	connAlpha := dialProxy(t, addr, pki, pki.clientCert(t, "alpha"))
	defer connAlpha.Close()

	resp := sendHTTPViaProxy(t, connAlpha, "GET", upstream.URL+"/api/users")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("alpha /api/users: status = %d, want 200", resp.StatusCode)
	}

	connAlpha2 := dialProxy(t, addr, pki, pki.clientCert(t, "alpha"))
	defer connAlpha2.Close()

	resp = sendHTTPViaProxy(t, connAlpha2, "GET", upstream.URL+"/data/files")
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("alpha /data/files: status = %d, want 403", resp.StatusCode)
	}

	// Beta can access /data but not /api
	connBeta := dialProxy(t, addr, pki, pki.clientCert(t, "beta"))
	defer connBeta.Close()

	resp = sendHTTPViaProxy(t, connBeta, "GET", upstream.URL+"/data/files")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("beta /data/files: status = %d, want 200", resp.StatusCode)
	}

	connBeta2 := dialProxy(t, addr, pki, pki.clientCert(t, "beta"))
	defer connBeta2.Close()

	resp = sendHTTPViaProxy(t, connBeta2, "GET", upstream.URL+"/api/users")
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("beta /api/users: status = %d, want 403", resp.StatusCode)
	}
}

func TestMultiTenantTelemetryTenantID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)

	pki := newTestPKI(t)

	engine, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
		{Name: "allow", Host: upURL.Hostname(), Path: "/**", Action: "allow"},
	})

	store := &memoryStore{tenants: map[string]*tenant.Tenant{
		"agent-42": {ID: "agent-42", Policy: engine, Secrets: secrets.NewChain()},
	}}

	addr, _, exp := startMTLSProxy(t, pki, store)

	conn := dialProxy(t, addr, pki, pki.clientCert(t, "agent-42"))
	defer conn.Close()

	resp := sendHTTPViaProxy(t, conn, "GET", upstream.URL+"/test")
	resp.Body.Close()

	entries := exp.getEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].TenantID != "agent-42" {
		t.Errorf("tenant_id = %q, want %q", entries[0].TenantID, "agent-42")
	}
}

func TestSingleTenantNoTenantID(t *testing.T) {
	engine, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
		{Name: "allow", Host: "example.com", Path: "/**", Action: "allow"},
	})
	exp := &collectExporter{}

	mitmCA, _ := wardenca.NewAutoCA("")
	resolver := wardendns.NewStdlibResolver(nil)
	denylist, _ := wardendns.NewDenylist(nil)

	p := New(Config{
		CA:        mitmCA,
		Tenants:   NewSingleTenantResolver(engine, secrets.NewChain()),
		Resolver:  resolver,
		Denylist:  denylist,
		Telemetry: exp,
	})

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	entries := exp.getEntries()
	if len(entries) == 0 {
		t.Fatal("expected log entry")
	}
	if entries[0].TenantID != "" {
		t.Errorf("single-tenant should have empty tenant_id, got %q", entries[0].TenantID)
	}
}
