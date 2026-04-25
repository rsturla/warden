//go:build linux

package bridge

import (
	"context"
	"net"

	"github.com/mdlayher/vsock"
)

type VsockDialer struct {
	CID  uint32
	Port uint32
}

func (d *VsockDialer) Dial(_ context.Context) (net.Conn, error) {
	return vsock.Dial(d.CID, d.Port, nil)
}
