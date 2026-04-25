package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAutoCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")

	ca, err := NewAutoCA(certPath)
	if err != nil {
		t.Fatal(err)
	}

	if !ca.CACert().IsCA {
		t.Error("cert should be CA")
	}
	if ca.CACert().KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("cert should have CertSign key usage")
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert output not written: %v", err)
	}

	certPEM, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid PEM output")
	}
}

func TestAutoCANoCertOutput(t *testing.T) {
	ca, err := NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}
	if !ca.CACert().IsCA {
		t.Error("cert should be CA")
	}
}

func TestGetOrCreateCert(t *testing.T) {
	ca, err := NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := ca.GetOrCreateCert("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.Subject.CommonName != "api.github.com" {
		t.Errorf("CN = %q", cert.Leaf.Subject.CommonName)
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "api.github.com" {
		t.Errorf("SAN = %v", cert.Leaf.DNSNames)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.CACert())
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("leaf cert does not verify against CA: %v", err)
	}
}

func TestGetOrCreateCertIP(t *testing.T) {
	ca, err := NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := ca.GetOrCreateCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.IPAddresses) != 1 {
		t.Fatalf("expected 1 IP SAN, got %d", len(cert.Leaf.IPAddresses))
	}
	if !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP SAN = %v", cert.Leaf.IPAddresses)
	}
}

func TestGetOrCreateCertCache(t *testing.T) {
	ca, err := NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}

	cert1, _ := ca.GetOrCreateCert("example.com")
	cert2, _ := ca.GetOrCreateCert("example.com")
	if cert1 != cert2 {
		t.Error("same host should return cached cert")
	}

	cert3, _ := ca.GetOrCreateCert("other.com")
	if cert1 == cert3 {
		t.Error("different host should return different cert")
	}
}

func TestGetOrCreateCertConcurrent(t *testing.T) {
	ca, err := NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan *tls.Certificate, 100)
	for range 100 {
		go func() {
			cert, err := ca.GetOrCreateCert("concurrent.test")
			if err != nil {
				t.Error(err)
			}
			done <- cert
		}()
	}

	var first *tls.Certificate
	for range 100 {
		c := <-done
		if first == nil {
			first = c
		} else if c != first {
			t.Error("concurrent calls should return same cached cert")
		}
	}
}

func TestTLSHandshake(t *testing.T) {
	ca, err := NewAutoCA("")
	if err != nil {
		t.Fatal(err)
	}

	serverConf := ca.TLSConfigForClient()

	pool := x509.NewCertPool()
	pool.AddCert(ca.CACert())
	clientConf := &tls.Config{
		RootCAs:    pool,
		ServerName: "test.example.com",
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 2)
	go func() {
		tlsServer := tls.Server(server, serverConf)
		errCh <- tlsServer.Handshake()
	}()
	go func() {
		tlsClient := tls.Client(client, clientConf)
		errCh <- tlsClient.Handshake()
	}()

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("TLS handshake failed: %v", err)
		}
	}
}

func TestExternalCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(certPath, certPEM, 0o600)
	os.WriteFile(keyPath, keyPEM, 0o600)

	ca, err := NewExternalCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.CACert().IsCA {
		t.Error("loaded cert should be CA")
	}

	leaf, err := ca.GetOrCreateCert("test.com")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf.Subject.CommonName != "test.com" {
		t.Errorf("CN = %q", leaf.Leaf.Subject.CommonName)
	}
}

func TestExternalCANotCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "notca.crt")
	keyPath := filepath.Join(dir, "notca.key")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Not a CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(certPath, certPEM, 0o600)
	os.WriteFile(keyPath, keyPEM, 0o600)

	_, err := NewExternalCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for non-CA cert")
	}
}

func TestCACertPEM(t *testing.T) {
	ca, _ := NewAutoCA("")
	pemBytes := ca.CACertPEM()
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid PEM")
	}
}
