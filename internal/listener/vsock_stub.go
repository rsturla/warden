//go:build !linux

package listener

import (
	"fmt"
	"net"
)

func init() {
	RegisterScheme("vsock", func(_ string) (net.Listener, error) {
		return nil, fmt.Errorf("vsock is only supported on linux")
	})
}
