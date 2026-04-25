//go:build !linux

package bridge

import (
	"context"
	"fmt"
	"net"
)

type VsockDialer struct {
	CID  uint32
	Port uint32
}

func (d *VsockDialer) Dial(_ context.Context) (net.Conn, error) {
	return nil, fmt.Errorf("vsock is only supported on linux")
}
