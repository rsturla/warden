package bridge

import (
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
	"os"
	"testing"
	"time"
)

func TestTLSDialer(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &serverKey.PublicKey, serverKey)
	serverCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverKey,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("hello-tls"))
	}()

	certPool := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(certDER)
	certPool.AddCert(cert)

	dialer := &TLSDialer{
		Addr: ln.Addr().String(),
		TLSConfig: &tls.Config{
			RootCAs: certPool,
		},
	}

	conn, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello-tls" {
		t.Errorf("got %q, want %q", buf, "hello-tls")
	}
}

func TestTLSDialerWithClientCert(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
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

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-agent"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	clientCertTLS := tls.Certificate{
		Certificate: [][]byte{clientCertDER},
		PrivateKey:  clientKey,
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(caCert)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var gotCN string
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			gotCN = state.PeerCertificates[0].Subject.CommonName
		}
		_, _ = conn.Write([]byte("authed"))
	}()

	serverCAPool := x509.NewCertPool()
	serverCAPool.AddCert(caCert)

	dialer := &TLSDialer{
		Addr: ln.Addr().String(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCertTLS},
			RootCAs:      serverCAPool,
		},
	}

	conn, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "authed" {
		t.Errorf("got %q, want %q", buf, "authed")
	}
	if gotCN != "test-agent" {
		t.Errorf("server saw CN = %q, want %q", gotCN, "test-agent")
	}
}

func TestTLSDialerClientCertReload(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	genClientCert := func(cn string) (tls.Certificate, []byte, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(1 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, _ := x509.MarshalECPrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		tlsCert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
		return tlsCert, certPEM, keyPEM
	}

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	serverCert := tls.Certificate{Certificate: [][]byte{serverCertDER}, PrivateKey: serverKey}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(caCert)

	cnCh := make(chan string, 10)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	})
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				continue
			}
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cnCh <- state.PeerCertificates[0].Subject.CommonName
			}
			conn.Write([]byte("ok"))
			conn.Close()
		}
	}()

	// Write first cert to disk
	certDir := t.TempDir()
	certPath := certDir + "/client.crt"
	keyPath := certDir + "/client.key"

	_, certPEM1, keyPEM1 := genClientCert("agent-v1")
	os.WriteFile(certPath, certPEM1, 0o600)
	os.WriteFile(keyPath, keyPEM1, 0o600)

	serverCAPool2 := x509.NewCertPool()
	serverCAPool2.AddCert(caCert)

	dialer := &TLSDialer{
		Addr: ln.Addr().String(),
		TLSConfig: &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(certPath, keyPath)
				if err != nil {
					return nil, err
				}
				return &cert, nil
			},
			RootCAs: serverCAPool2,
		},
	}

	// First connection — should see agent-v1
	conn1, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	io.ReadAll(conn1)
	conn1.Close()

	cn1 := <-cnCh
	if cn1 != "agent-v1" {
		t.Errorf("first connection CN = %q, want %q", cn1, "agent-v1")
	}

	// Replace cert on disk with new CN
	_, certPEM2, keyPEM2 := genClientCert("agent-v2")
	os.WriteFile(certPath, certPEM2, 0o600)
	os.WriteFile(keyPath, keyPEM2, 0o600)

	// Second connection — should see agent-v2 (reloaded from disk)
	conn2, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	io.ReadAll(conn2)
	conn2.Close()

	cn2 := <-cnCh
	if cn2 != "agent-v2" {
		t.Errorf("second connection CN = %q, want %q (cert was not reloaded)", cn2, "agent-v2")
	}
}

func TestTLSDialerServerCertReload(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	genServerCert := func(cn string) ([]byte, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(1 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, _ := x509.MarshalECPrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		return certPEM, keyPEM
	}

	certDir := t.TempDir()
	certPath := certDir + "/server.crt"
	keyPath := certDir + "/server.key"

	certPEM1, keyPEM1 := genServerCert("server-v1")
	os.WriteFile(certPath, certPEM1, 0o600)
	os.WriteFile(keyPath, keyPEM1, 0o600)

	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
		MinVersion: tls.VersionTLS12,
	})
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("ok"))
			conn.Close()
		}
	}()

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	dial := func() string {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		io.ReadAll(conn)
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}

	// First connection — server-v1
	cn1 := dial()
	if cn1 != "server-v1" {
		t.Errorf("first connection CN = %q, want %q", cn1, "server-v1")
	}

	// Replace server cert on disk
	certPEM2, keyPEM2 := genServerCert("server-v2")
	os.WriteFile(certPath, certPEM2, 0o600)
	os.WriteFile(keyPath, keyPEM2, 0o600)

	// Second connection — server-v2
	cn2 := dial()
	if cn2 != "server-v2" {
		t.Errorf("second connection CN = %q, want %q (cert was not reloaded)", cn2, "server-v2")
	}
}

func TestTLSDialerConnectionRefused(t *testing.T) {
	dialer := &TLSDialer{
		Addr: "127.0.0.1:1",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	_, err := dialer.Dial(context.Background())
	if err == nil {
		t.Fatal("expected error for refused connection")
	}
}
