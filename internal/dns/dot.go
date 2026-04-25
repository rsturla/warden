package dns

import (
	"context"
	"crypto/tls"
	"net"
)

type DoTResolver struct {
	resolver *net.Resolver
}

func NewDoTResolver(server string) *DoTResolver {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		server = net.JoinHostPort(server, "853")
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			conn, err := d.DialContext(ctx, "tcp", server)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	return &DoTResolver{resolver: r}
}

func (r *DoTResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := r.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}
