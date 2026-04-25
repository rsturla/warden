package dns

import (
	"net"
	"testing"
)

func FuzzDenylistCheck(f *testing.F) {
	f.Add("10.0.0.1")
	f.Add("8.8.8.8")
	f.Add("127.0.0.1")
	f.Add("::1")
	f.Add("192.168.1.1")
	f.Add("255.255.255.255")
	f.Add("")

	d, _ := NewDenylist([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
	})

	f.Fuzz(func(t *testing.T, ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		d.Check("test.com", []net.IP{ip})
	})
}
