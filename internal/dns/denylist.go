package dns

import (
	"fmt"
	"net"
	"net/netip"
)

type Denylist struct {
	prefixes []netip.Prefix
}

func NewDenylist(cidrs []string) (*Denylist, error) {
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		prefixes[i] = p
	}
	return &Denylist{prefixes: prefixes}, nil
}

func (d *Denylist) Check(host string, ips []net.IP) error {
	if len(d.prefixes) == 0 {
		return nil
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		for _, prefix := range d.prefixes {
			if prefix.Contains(addr) {
				return fmt.Errorf("host %q resolved to denied IP %s (in %s)", host, ip, prefix)
			}
		}
	}
	return nil
}
