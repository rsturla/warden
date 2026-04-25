package dns

import (
	"net"
	"testing"
)

func stdDenylist(t *testing.T) *Denylist {
	t.Helper()
	d, err := NewDenylist([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"::1/128",
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDenylistBlocked(t *testing.T) {
	d := stdDenylist(t)
	tests := []struct {
		ip   string
		host string
	}{
		{"10.0.0.1", "internal.example.com"},
		{"172.16.5.1", "vpn.example.com"},
		{"192.168.1.1", "router.local"},
		{"169.254.169.254", "metadata.cloud"},
		{"127.0.0.1", "localhost"},
	}
	for _, tt := range tests {
		err := d.Check(tt.host, []net.IP{net.ParseIP(tt.ip)})
		if err == nil {
			t.Errorf("expected %s (%s) to be blocked", tt.ip, tt.host)
		}
	}
}

func TestDenylistIPv6Blocked(t *testing.T) {
	d := stdDenylist(t)
	err := d.Check("localhost", []net.IP{net.ParseIP("::1")})
	if err == nil {
		t.Error("expected ::1 to be blocked")
	}
}

func TestDenylistAllowed(t *testing.T) {
	d := stdDenylist(t)
	allowed := []string{"8.8.8.8", "1.2.3.4", "203.0.113.1", "2001:db8::1"}
	for _, ip := range allowed {
		err := d.Check("test.com", []net.IP{net.ParseIP(ip)})
		if err != nil {
			t.Errorf("%s should be allowed: %v", ip, err)
		}
	}
}

func TestDenylistMultipleIPs(t *testing.T) {
	d := stdDenylist(t)
	err := d.Check("test.com", []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("10.0.0.1"),
	})
	if err == nil {
		t.Error("should block when any IP is denied")
	}
}

func TestDenylistEmpty(t *testing.T) {
	d, _ := NewDenylist(nil)
	err := d.Check("test.com", []net.IP{net.ParseIP("10.0.0.1")})
	if err != nil {
		t.Errorf("empty denylist should allow everything: %v", err)
	}
}

func TestDenylistCIDRBoundary(t *testing.T) {
	d, _ := NewDenylist([]string{"10.0.0.0/8"})

	boundary := []struct {
		ip      string
		blocked bool
	}{
		{"10.0.0.0", true},
		{"10.255.255.255", true},
		{"9.255.255.255", false},
		{"11.0.0.0", false},
	}
	for _, tt := range boundary {
		err := d.Check("test", []net.IP{net.ParseIP(tt.ip)})
		if (err != nil) != tt.blocked {
			t.Errorf("%s: blocked=%v, want %v", tt.ip, err != nil, tt.blocked)
		}
	}
}

func TestDenylistIPv4MappedIPv6(t *testing.T) {
	d, _ := NewDenylist([]string{"10.0.0.0/8"})
	// ::ffff:10.0.0.1 is IPv4-mapped IPv6 for 10.0.0.1
	ip := net.ParseIP("::ffff:10.0.0.1")
	err := d.Check("test", []net.IP{ip})
	if err == nil {
		t.Error("IPv4-mapped IPv6 10.0.0.1 should be blocked")
	}
}

func TestDenylistInvalidCIDR(t *testing.T) {
	_, err := NewDenylist([]string{"not-a-cidr"})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}
