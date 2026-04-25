package listener

import (
	"testing"
)

func TestNewTCP(t *testing.T) {
	l, err := New("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if l.Addr().Network() != "tcp" {
		t.Errorf("network = %q", l.Addr().Network())
	}
}

func TestNewInvalidAddress(t *testing.T) {
	_, err := New(":::invalid")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestNewVsockParseError(t *testing.T) {
	_, err := New("vsock://:notanumber")
	if err == nil {
		t.Error("expected error for invalid vsock port")
	}
}
