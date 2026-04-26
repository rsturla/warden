package tenant

import (
	"fmt"

	"github.com/rsturla/warden/internal/config"
	"go.yaml.in/yaml/v3"
)

type TenantConfig struct {
	Policies []config.PolicyRule   `yaml:"policies"`
	Secrets  []config.SecretConfig `yaml:"secrets"`
}

func ParseTenantConfig(data []byte) (*TenantConfig, error) {
	var tc TenantConfig
	if err := yaml.Unmarshal(data, &tc); err != nil {
		return nil, fmt.Errorf("parsing tenant config: %w", err)
	}
	if err := validateTenantConfig(&tc); err != nil {
		return nil, err
	}
	applyTenantDefaults(&tc)
	return &tc, nil
}

func applyTenantDefaults(tc *TenantConfig) {
	for i := range tc.Policies {
		if tc.Policies[i].Path == "" {
			tc.Policies[i].Path = "/**"
		}
	}
}

func validateTenantConfig(tc *TenantConfig) error {
	seen := make(map[string]bool)
	for i, p := range tc.Policies {
		if p.Name == "" {
			return fmt.Errorf("policy %d: name is required", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("policy %q: duplicate name", p.Name)
		}
		seen[p.Name] = true
		if p.Host == "" {
			return fmt.Errorf("policy %q: host is required", p.Name)
		}
		if p.Action == "" {
			return fmt.Errorf("policy %q: action is required", p.Name)
		}
		if p.Action != "allow" && p.Action != "deny" {
			return fmt.Errorf("policy %q: action must be 'allow' or 'deny', got %q", p.Name, p.Action)
		}
		if p.Action == "deny" && p.Inject != nil {
			return fmt.Errorf("policy %q: deny rules cannot have inject", p.Name)
		}
	}
	for _, s := range tc.Secrets {
		if s.Type == "" {
			return fmt.Errorf("secret source: type is required")
		}
	}
	return nil
}
