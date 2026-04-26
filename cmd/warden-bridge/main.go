package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/rsturla/warden/internal/bridge"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:8080", "TCP listen address")

	// vsock mode
	vsockCID := flag.Uint("vsock-cid", 0, "vsock context ID (2 = host)")
	vsockPort := flag.Uint("vsock-port", 0, "vsock port")

	// TLS proxy mode
	proxyAddr := flag.String("proxy-addr", "", "TCP address of Warden proxy (TLS mode)")
	clientCert := flag.String("client-cert", "", "client certificate for proxy mTLS (PEM)")
	clientKey := flag.String("client-key", "", "client key for proxy mTLS (PEM)")
	proxyCA := flag.String("proxy-ca", "", "CA certificate to verify proxy server (PEM)")

	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	dialer, mode, err := buildDialer(*vsockCID, *vsockPort, *proxyAddr, *clientCert, *clientKey, *proxyCA)
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}
	defer l.Close()

	b := bridge.New(l, dialer, logger)

	logAttrs := []any{"listen", *listenAddr, "mode", mode}
	if mode == "vsock" {
		logAttrs = append(logAttrs, "vsock_cid", *vsockCID, "vsock_port", *vsockPort)
	} else {
		logAttrs = append(logAttrs, "proxy_addr", *proxyAddr)
	}
	slog.Info("warden-bridge starting", logAttrs...)

	if err := b.Serve(ctx); err != nil {
		slog.Error("bridge error", "error", err)
		os.Exit(1)
	}
}

func buildDialer(vsockCID, vsockPort uint, proxyAddr, certPath, keyPath, caPath string) (bridge.Dialer, string, error) {
	vsockMode := vsockCID > 0 || vsockPort > 0
	tlsMode := proxyAddr != ""

	if vsockMode && tlsMode {
		return nil, "", fmt.Errorf("cannot use both vsock and TLS proxy mode")
	}
	if !vsockMode && !tlsMode {
		return nil, "", fmt.Errorf("specify either --vsock-cid/--vsock-port or --proxy-addr")
	}

	if vsockMode {
		const maxUint32 = 1<<32 - 1
		if vsockCID > maxUint32 || vsockPort > maxUint32 {
			return nil, "", fmt.Errorf("vsock CID and port must fit in uint32")
		}
		cid := uint32(vsockCID)   // #nosec G115 -- bounds checked above
		port := uint32(vsockPort) // #nosec G115 -- bounds checked above
		return &bridge.VsockDialer{CID: cid, Port: port}, "vsock", nil
	}

	if certPath == "" || keyPath == "" {
		return nil, "", fmt.Errorf("--client-cert and --client-key required for TLS proxy mode")
	}

	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return nil, "", fmt.Errorf("loading client certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
		MinVersion: tls.VersionTLS12,
	}

	if caPath != "" {
		caPEM, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			return nil, "", fmt.Errorf("reading proxy CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, "", fmt.Errorf("no valid certificates found in %s", caPath)
		}
		tlsCfg.RootCAs = pool
	}

	return &bridge.TLSDialer{Addr: proxyAddr, TLSConfig: tlsCfg}, "tls", nil
}
