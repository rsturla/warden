package config

import (
	"testing"
)

func TestParseFullConfig(t *testing.T) {
	data := []byte(`
server:
  listen: "0.0.0.0:8080"
  health_listen: "0.0.0.0:9090"
ca:
  auto: true
  cert_output: /shared/warden-ca.crt
dns:
  servers: ["8.8.8.8:53"]
  cache:
    enabled: true
    max_ttl: 600
  deny_resolved_ips:
    - "10.0.0.0/8"
    - "127.0.0.0/8"
secrets:
  - type: env
  - type: file
    path: /run/secrets
policies:
  - name: deny-metadata
    host: "169.254.169.254"
    action: deny
  - name: allow-github
    host: "api.github.com"
    path: "/repos/**"
    methods: ["GET", "POST"]
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${GITHUB_TOKEN}"
      query:
        foo: "bar"
telemetry:
  logs:
    level: info
    format: json
  traces:
    enabled: true
    endpoint: "http://otel:4317"
`)

	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Listen != "0.0.0.0:8080" {
		t.Errorf("listen = %q, want %q", cfg.Server.Listen, "0.0.0.0:8080")
	}
	if cfg.CA.Auto != true {
		t.Error("ca.auto should be true")
	}
	if len(cfg.DNS.Servers) != 1 {
		t.Errorf("dns.servers len = %d, want 1", len(cfg.DNS.Servers))
	}
	if cfg.DNS.Cache.MaxTTL != 600 {
		t.Errorf("dns.cache.max_ttl = %d, want 600", cfg.DNS.Cache.MaxTTL)
	}
	if len(cfg.Secrets) != 2 {
		t.Errorf("secrets len = %d, want 2", len(cfg.Secrets))
	}
	if len(cfg.Policies) != 2 {
		t.Errorf("policies len = %d, want 2", len(cfg.Policies))
	}
	if cfg.Policies[1].Inject == nil {
		t.Fatal("policy 1 inject should not be nil")
	}
	if cfg.Policies[1].Inject.Headers["Authorization"] != "Bearer ${GITHUB_TOKEN}" {
		t.Errorf("inject header = %q", cfg.Policies[1].Inject.Headers["Authorization"])
	}
	if cfg.Policies[1].Inject.Query["foo"] != "bar" {
		t.Errorf("inject query = %q", cfg.Policies[1].Inject.Query["foo"])
	}
}

func TestParseMinimalConfig(t *testing.T) {
	data := []byte(`
policies: []
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Listen != "0.0.0.0:8080" {
		t.Errorf("default listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.HealthListen != "0.0.0.0:9090" {
		t.Errorf("default health_listen = %q", cfg.Server.HealthListen)
	}
	if cfg.Telemetry.Logs.Level != "info" {
		t.Errorf("default log level = %q", cfg.Telemetry.Logs.Level)
	}
	if cfg.Telemetry.Logs.Format != "json" {
		t.Errorf("default log format = %q", cfg.Telemetry.Logs.Format)
	}
	if cfg.DNS.Cache.MaxTTL != 300 {
		t.Errorf("default max_ttl = %d", cfg.DNS.Cache.MaxTTL)
	}
}

func TestParsePathDefault(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    action: allow
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Policies[0].Path != "/**" {
		t.Errorf("default path = %q, want %q", cfg.Policies[0].Path, "/**")
	}
}

func TestValidateMissingName(t *testing.T) {
	data := []byte(`
policies:
  - host: "example.com"
    action: allow
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestValidateMissingHost(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    action: allow
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestValidateMissingAction(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing action")
	}
}

func TestValidateInvalidAction(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    action: maybe
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestValidateDuplicateName(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "a.com"
    action: allow
  - name: test
    host: "b.com"
    action: deny
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestValidateDenyWithInject(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    action: deny
    inject:
      headers:
        X-Foo: bar
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for deny with inject")
	}
}

func TestValidateLowercaseMethod(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    methods: ["get"]
    action: allow
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for lowercase method")
	}
}

func TestValidateInvalidSecretType(t *testing.T) {
	data := []byte(`
secrets:
  - type: redis
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for unsupported secret type")
	}
}

func TestValidateVaultSecretMissingAddress(t *testing.T) {
	data := []byte(`
secrets:
  - type: vault
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for vault secret without address")
	}
}

func TestValidateVaultSecretValid(t *testing.T) {
	data := []byte(`
secrets:
  - type: vault
    address: https://vault.example.com:8200
policies: []
`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("valid vault config rejected: %v", err)
	}
}

func TestValidateGitHubAppSecretMissingFields(t *testing.T) {
	data := []byte(`
secrets:
  - type: github-app
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for github-app without required fields")
	}
}

func TestValidateKubernetesSecretValid(t *testing.T) {
	data := []byte(`
secrets:
  - type: kubernetes
policies: []
`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("kubernetes secret should be valid: %v", err)
	}
}

func TestValidateDoTMissingServer(t *testing.T) {
	data := []byte(`
dns:
  dot:
    enabled: true
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for dot enabled without server")
	}
}

func TestValidateTracesEnabledMissingEndpoint(t *testing.T) {
	data := []byte(`
telemetry:
  traces:
    enabled: true
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for traces enabled without endpoint")
	}
}

func TestValidateFileSecretMissingPath(t *testing.T) {
	data := []byte(`
secrets:
  - type: file
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for file secret without path")
	}
}

func TestValidateInvalidCIDR(t *testing.T) {
	data := []byte(`
dns:
  deny_resolved_ips:
    - "not-a-cidr"
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestValidateEmptyPolicies(t *testing.T) {
	data := []byte(`policies: []`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("empty policies should be valid: %v", err)
	}
}

func TestParseInvalidYAML(t *testing.T) {
	data := []byte(`{{{invalid`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadValidFile(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatalf("failed to load example config: %v", err)
	}
	if len(cfg.Policies) == 0 {
		t.Error("expected policies in example config")
	}
}

func TestValidateMixedCaseAction(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    action: Allow
`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("mixed case action should be accepted: %v", err)
	}
}

func TestValidateIPv6CIDR(t *testing.T) {
	data := []byte(`
dns:
  deny_resolved_ips:
    - "::1/128"
    - "fe80::/10"
policies: []
`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("IPv6 CIDRs should be valid: %v", err)
	}
}

func TestValidateSpecialCharsInPolicyName(t *testing.T) {
	data := []byte(`
policies:
  - name: "allow-github.com/repos"
    host: "api.github.com"
    action: allow
`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("special chars in policy name should be valid: %v", err)
	}
}

func TestValidateTenantsRequiresTLS(t *testing.T) {
	data := []byte(`
tenants:
  dir: /etc/warden/tenants.d
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: tenants without server.tls")
	}
}

func TestValidateTenantsRequiresDir(t *testing.T) {
	data := []byte(`
server:
  tls:
    cert: server.crt
    key: server.key
    client_ca: ca.crt
tenants: {}
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: tenants without dir")
	}
}

func TestValidateTenantsRejectsPolicies(t *testing.T) {
	data := []byte(`
server:
  tls:
    cert: server.crt
    key: server.key
    client_ca: ca.crt
tenants:
  dir: /etc/warden/tenants.d
policies:
  - name: test
    host: "example.com"
    action: allow
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: tenants with root-level policies")
	}
}

func TestValidateTenantsRejectsSecrets(t *testing.T) {
	data := []byte(`
server:
  tls:
    cert: server.crt
    key: server.key
    client_ca: ca.crt
tenants:
  dir: /etc/warden/tenants.d
secrets:
  - type: env
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: tenants with root-level secrets")
	}
}

func TestValidateTenantsValid(t *testing.T) {
	data := []byte(`
server:
  tls:
    cert: server.crt
    key: server.key
    client_ca: ca.crt
tenants:
  dir: /etc/warden/tenants.d
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("valid tenant config rejected: %v", err)
	}
	if cfg.Tenants == nil {
		t.Fatal("tenants should not be nil")
	}
	if cfg.Tenants.Dir != "/etc/warden/tenants.d" {
		t.Errorf("tenants.dir = %q", cfg.Tenants.Dir)
	}
}

func TestValidateServerTLSMissingCert(t *testing.T) {
	data := []byte(`
server:
  tls:
    key: server.key
    client_ca: ca.crt
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: TLS without cert")
	}
}

func TestValidateServerTLSMissingKey(t *testing.T) {
	data := []byte(`
server:
  tls:
    cert: server.crt
    client_ca: ca.crt
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: TLS without key")
	}
}

func TestValidateServerTLSMissingClientCA(t *testing.T) {
	data := []byte(`
server:
  tls:
    cert: server.crt
    key: server.key
policies: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: TLS without client_ca")
	}
}

func TestValidateEmptyMethodsList(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    methods: []
    action: allow
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policies[0].Methods) != 0 {
		t.Error("empty methods should remain empty (match all)")
	}
}
