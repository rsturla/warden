package dns

import (
	"context"
	"net"
)

type Resolver interface {
	Resolve(ctx context.Context, host string) ([]net.IP, error)
}

type StdlibResolver struct {
	resolver *net.Resolver
}

func NewStdlibResolver(servers []string) *StdlibResolver {
	r := &net.Resolver{PreferGo: true}

	if len(servers) > 0 {
		r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", servers[0])
		}
	}

	return &StdlibResolver{resolver: r}
}

func (r *StdlibResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
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
