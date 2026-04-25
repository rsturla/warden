package dns

import (
	"context"
	"net"
	"testing"
)

func TestStdlibResolverIP(t *testing.T) {
	r := NewStdlibResolver(nil)
	ips, err := r.Resolve(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("ips = %v", ips)
	}
}

func TestStdlibResolverLocalhost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DNS test in short mode")
	}
	r := NewStdlibResolver(nil)
	ips, err := r.Resolve(context.Background(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Error("expected at least one IP for localhost")
	}
}
