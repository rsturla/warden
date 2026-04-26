package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/rsturla/warden/internal/config"
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
	"github.com/rsturla/warden/internal/tenant"
)

func TestSingleTenantResolverAlwaysReturns(t *testing.T) {
	engine, _ := policy.NewYAMLPolicyEngine([]config.PolicyRule{
		{Name: "test", Host: "example.com", Path: "/**", Action: "allow"},
	})
	chain := secrets.NewChain()

	resolver := NewSingleTenantResolver(engine, chain)

	r1, _ := http.NewRequest("GET", "http://example.com", nil)
	rt1, err := resolver.Resolve(r1)
	if err != nil {
		t.Fatal(err)
	}

	r2, _ := http.NewRequest("POST", "http://other.com/path", nil)
	rt2, err := resolver.Resolve(r2)
	if err != nil {
		t.Fatal(err)
	}

	if rt1 != rt2 {
		t.Error("single tenant resolver should return same instance")
	}
	if rt1.id != "" {
		t.Errorf("single tenant should have empty id, got %q", rt1.id)
	}
	if rt1.policy == nil {
		t.Error("policy should not be nil")
	}
	if rt1.secrets == nil {
		t.Error("secrets should not be nil")
	}
}

func TestMTLSResolverNoCert(t *testing.T) {
	store := &memoryStore{tenants: map[string]*tenant.Tenant{}}
	resolver := NewMTLSTenantResolver(store)

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err := resolver.Resolve(r)
	if err == nil {
		t.Fatal("expected error for request without TLS")
	}
}

func TestMTLSResolverNoPeerCerts(t *testing.T) {
	store := &memoryStore{tenants: map[string]*tenant.Tenant{}}
	resolver := NewMTLSTenantResolver(store)

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.TLS = &tls.ConnectionState{}
	_, err := resolver.Resolve(r)
	if err == nil {
		t.Fatal("expected error for TLS without peer certs")
	}
}

func TestMTLSResolverValidCert(t *testing.T) {
	engine, _ := policy.NewYAMLPolicyEngine(nil)
	store := &memoryStore{tenants: map[string]*tenant.Tenant{
		"agent-alpha": {ID: "agent-alpha", Policy: engine, Secrets: secrets.NewChain()},
	}}
	resolver := NewMTLSTenantResolver(store)

	cert := makeCert(t, "agent-alpha")
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	rt, err := resolver.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	if rt.id != "agent-alpha" {
		t.Errorf("tenant id = %q, want %q", rt.id, "agent-alpha")
	}
}

func TestMTLSResolverUnknownTenant(t *testing.T) {
	store := &memoryStore{tenants: map[string]*tenant.Tenant{}}
	resolver := NewMTLSTenantResolver(store)

	cert := makeCert(t, "unknown-agent")
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	_, err := resolver.Resolve(r)
	if err == nil {
		t.Fatal("expected error for unknown tenant")
	}
}

func makeCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}
