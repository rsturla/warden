// Package api defines types shared between the Warden proxy and operator.
// These types are the serialization contract — the operator writes YAML
// using these types, and the proxy parses it via ParseTenantConfig.
package api

type PolicyRule struct {
	Name    string        `yaml:"name" json:"name"`
	Host    string        `yaml:"host" json:"host"`
	Path    string        `yaml:"path,omitempty" json:"path,omitempty"`
	Methods []string      `yaml:"methods,omitempty" json:"methods,omitempty"`
	Action  string        `yaml:"action" json:"action"`
	Inject  *InjectConfig `yaml:"inject,omitempty" json:"inject,omitempty"`
}

type InjectConfig struct {
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Query   map[string]string `yaml:"query,omitempty" json:"query,omitempty"`
}

type SecretConfig struct {
	Type       string                `yaml:"type" json:"type"`
	File       FileSecretConfig      `yaml:",inline"`
	Vault      VaultSecretConfig     `yaml:",inline"`
	Kubernetes K8sSecretConfig       `yaml:",inline"`
	GitHubApp  GitHubAppSecretConfig `yaml:",inline"`
}

type FileSecretConfig struct {
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

type VaultSecretConfig struct {
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
	Mount   string `yaml:"mount,omitempty" json:"mount,omitempty"`
	Prefix  string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Auth    string `yaml:"auth,omitempty" json:"auth,omitempty"`
}

type K8sSecretConfig struct {
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

type GitHubAppSecretConfig struct {
	AppID          int64  `yaml:"app_id,omitempty" json:"appId,omitempty"`
	InstallationID int64  `yaml:"installation_id,omitempty" json:"installationId,omitempty"`
	PrivateKeyPath string `yaml:"private_key_path,omitempty" json:"privateKeyPath,omitempty"`
}

type TenantConfig struct {
	Policies []PolicyRule   `yaml:"policies" json:"policies"`
	Secrets  []SecretConfig `yaml:"secrets" json:"secrets"`
}
