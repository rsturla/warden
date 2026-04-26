package config

import (
	"fmt"
	"sync"
)

type SecretValidator func(SecretConfig) error

var (
	secretValidatorsMu sync.RWMutex
	secretValidators   = map[string]SecretValidator{}
)

func RegisterSecretValidator(name string, v SecretValidator) {
	secretValidatorsMu.Lock()
	defer secretValidatorsMu.Unlock()
	secretValidators[name] = v
}

func validateSecret(s SecretConfig) error {
	secretValidatorsMu.RLock()
	v, ok := secretValidators[s.Type]
	secretValidatorsMu.RUnlock()
	if !ok {
		return fmt.Errorf("secret source type %q not supported", s.Type)
	}
	if v != nil {
		return v(s)
	}
	return nil
}
