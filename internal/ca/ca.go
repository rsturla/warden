package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CertProvider interface {
	GetOrCreateCert(host string) (*tls.Certificate, error)
}

type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	tlsCert tls.Certificate

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

func NewAutoCA(certOutput string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Warden CA"},
			CommonName:   "Warden Auto-Generated CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}

	if certOutput != "" {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err := os.WriteFile(filepath.Clean(certOutput), certPEM, 0o600); err != nil {
			return nil, fmt.Errorf("writing CA cert to %s: %w", certOutput, err)
		}
	}

	return &CA{
		cert:    cert,
		key:     key,
		tlsCert: tlsCert,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func NewExternalCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, fmt.Errorf("reading CA key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading CA key pair: %w", err)
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA")
	}

	key, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key must be ECDSA, got %T", tlsCert.PrivateKey)
	}

	tlsCert.Leaf = cert

	return &CA{
		cert:    cert,
		key:     key,
		tlsCert: tlsCert,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func (ca *CA) GetOrCreateCert(host string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if c, ok := ca.cache[host]; ok {
		ca.mu.RUnlock()
		return c, nil
	}
	ca.mu.RUnlock()

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Double-check after acquiring write lock
	if c, ok := ca.cache[host]; ok {
		return c, nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("signing leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.tlsCert.Certificate[0]},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}

	ca.cache[host] = tlsCert
	return tlsCert, nil
}

func (ca *CA) TLSConfigForClient() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ca.GetOrCreateCert(hello.ServerName)
		},
	}
}

func (ca *CA) CACert() *x509.Certificate {
	return ca.cert
}

func (ca *CA) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}
