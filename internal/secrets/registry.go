package secrets

import (
	"fmt"
	"sync"

	"github.com/rsturla/warden/internal/config"
)

type Factory func(cfg config.SecretConfig) (SecretSource, error)

var (
	registryMu sync.RWMutex
	factories  = map[string]Factory{}
)

func Register(name string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	factories[name] = f
}

func Build(cfg config.SecretConfig) (SecretSource, error) {
	registryMu.RLock()
	f, ok := factories[cfg.Type]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown secret source type: %q", cfg.Type)
	}
	return f(cfg)
}

func IsRegistered(name string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := factories[name]
	return ok
}
