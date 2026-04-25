//go:build linux

package listener

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mdlayher/vsock"
)

func init() {
	RegisterScheme("vsock", func(addr string) (net.Listener, error) {
		portStr := strings.TrimPrefix(addr, ":")
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vsock port %q: %w", portStr, err)
		}
		return vsock.Listen(uint32(port), nil)
	})
}
