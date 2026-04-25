//go:build !linux

package listener

import (
	"fmt"
	"net"
)

func newVsock(port uint32) (net.Listener, error) {
	return nil, fmt.Errorf("vsock is only supported on linux")
}
