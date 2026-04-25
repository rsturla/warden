package listener

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func New(addr string) (net.Listener, error) {
	if strings.HasPrefix(addr, "vsock://") {
		portStr := strings.TrimPrefix(addr, "vsock://:")
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vsock port %q: %w", portStr, err)
		}
		return newVsock(uint32(port))
	}
	return net.Listen("tcp", addr)
}
