package tenant

import (
	"testing"
)

func TestParseTenantConfigValid(t *testing.T) {
	data := []byte(`
policies:
  - name: allow-github
    host: "api.github.com"
    path: "/repos/**"
    methods: ["GET", "POST"]
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${TOKEN}"
  - name: deny-internal
    host: "internal.corp"
    action: deny
secrets:
  - type: env
`)
	tc, err := ParseTenantConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tc.Policies) != 2 {
		t.Errorf("policies len = %d, want 2", len(tc.Policies))
	}
	if len(tc.Secrets) != 1 {
		t.Errorf("secrets len = %d, want 1", len(tc.Secrets))
	}
	if tc.Policies[0].Inject == nil {
		t.Fatal("policy 0 inject should not be nil")
	}
	if tc.Policies[0].Inject.Headers["Authorization"] != "Bearer ${TOKEN}" {
		t.Errorf("inject header = %q", tc.Policies[0].Inject.Headers["Authorization"])
	}
}

func TestParseTenantConfigPathDefault(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    action: allow
`)
	tc, err := ParseTenantConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Policies[0].Path != "/**" {
		t.Errorf("default path = %q, want %q", tc.Policies[0].Path, "/**")
	}
}

func TestParseTenantConfigEmpty(t *testing.T) {
	data := []byte(`
policies: []
secrets: []
`)
	tc, err := ParseTenantConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Policies) != 0 {
		t.Errorf("expected empty policies")
	}
}

func TestParseTenantConfigMissingName(t *testing.T) {
	data := []byte(`
policies:
  - host: "example.com"
    action: allow
`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestParseTenantConfigMissingHost(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    action: allow
`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestParseTenantConfigMissingAction(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for missing action")
	}
}

func TestParseTenantConfigInvalidAction(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    action: maybe
`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestParseTenantConfigDuplicateName(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "a.com"
    action: allow
  - name: test
    host: "b.com"
    action: deny
`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestParseTenantConfigDenyWithInject(t *testing.T) {
	data := []byte(`
policies:
  - name: test
    host: "example.com"
    action: deny
    inject:
      headers:
        X-Foo: bar
`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for deny with inject")
	}
}

func TestParseTenantConfigInvalidYAML(t *testing.T) {
	data := []byte(`{{{invalid`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParseTenantConfigMissingSecretType(t *testing.T) {
	data := []byte(`
policies: []
secrets:
  - {}
`)
	_, err := ParseTenantConfig(data)
	if err == nil {
		t.Fatal("expected error for secret without type")
	}
}

func TestParseTenantConfigNoPoliciesKey(t *testing.T) {
	data := []byte(`
secrets:
  - type: env
`)
	tc, err := ParseTenantConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Policies) != 0 {
		t.Errorf("expected empty policies, got %d", len(tc.Policies))
	}
}
