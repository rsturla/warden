package dns

import (
	"context"
	"net"
	"testing"
)

func TestDoTResolverIPPassthrough(t *testing.T) {
	r := NewDoTResolver("1.1.1.1:853")

	ips, err := r.Resolve(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("got %v", ips)
	}
}

func TestDoTResolverIPv6Passthrough(t *testing.T) {
	r := NewDoTResolver("1.1.1.1:853")

	ips, err := r.Resolve(context.Background(), "::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("::1")) {
		t.Errorf("got %v", ips)
	}
}

func TestDoTResolverDefaultPort(t *testing.T) {
	r := NewDoTResolver("1.1.1.1")

	ips, err := r.Resolve(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 {
		t.Errorf("expected 1 IP, got %d", len(ips))
	}
}
