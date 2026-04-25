//go:build linux

package listener

import (
	"net"

	"github.com/mdlayher/vsock"
)

func newVsock(port uint32) (net.Listener, error) {
	return vsock.Listen(port, nil)
}
