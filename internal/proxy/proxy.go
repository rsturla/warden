package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	wardenca "github.com/rsturla/warden/internal/ca"
	wardendns "github.com/rsturla/warden/internal/dns"
	"github.com/rsturla/warden/internal/telemetry"
)

type Proxy struct {
	ca        wardenca.CertProvider
	tenants   TenantResolver
	resolver  wardendns.Resolver
	denylist  *wardendns.Denylist
	telemetry telemetry.TelemetryExporter
	transport *http.Transport
}

type Config struct {
	CA        wardenca.CertProvider
	Tenants   TenantResolver
	Resolver  wardendns.Resolver
	Denylist  *wardendns.Denylist
	Telemetry telemetry.TelemetryExporter
}

func New(cfg Config) *Proxy {
	p := &Proxy{
		ca:        cfg.CA,
		tenants:   cfg.Tenants,
		resolver:  cfg.Resolver,
		denylist:  cfg.Denylist,
		telemetry: cfg.Telemetry,
	}

	p.transport = &http.Transport{
		DialContext: p.dialWithDNS,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleForward(w, r)
	}
}

func (p *Proxy) dialWithDNS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := p.resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses resolved for %s", host)
	}

	if err := p.denylist.Check(host, ips); err != nil {
		return nil, err
	}

	var d net.Dialer
	d.Timeout = 5 * time.Second
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}
