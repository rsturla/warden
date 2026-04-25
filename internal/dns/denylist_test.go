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

func TestDenylistInvalidCIDR(t *testing.T) {
	_, err := NewDenylist([]string{"not-a-cidr"})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}
