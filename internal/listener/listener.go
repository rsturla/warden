package listener

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

type Factory func(addr string) (net.Listener, error)

var (
	registryMu sync.RWMutex
	schemes    = map[string]Factory{}
)

func RegisterScheme(scheme string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	schemes[scheme] = f
}

func init() {
	RegisterScheme("tcp", func(addr string) (net.Listener, error) {
		return net.Listen("tcp", addr)
	})
}

func New(addr string) (net.Listener, error) {
	scheme, rest := parseScheme(addr)
	registryMu.RLock()
	f, ok := schemes[scheme]
	registryMu.RUnlock()
	if ok {
		return f(rest)
	}
	return nil, fmt.Errorf("unknown listener scheme: %q", scheme)
}

func parseScheme(addr string) (string, string) {
	if i := strings.Index(addr, "://"); i >= 0 {
		return addr[:i], addr[i+3:]
	}
	return "tcp", addr
}
