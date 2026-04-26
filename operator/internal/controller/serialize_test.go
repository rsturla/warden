package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
	"github.com/rsturla/warden/internal/tenant"
	"github.com/rsturla/warden/pkg/api"
)

func TestSerializeTenantConfig_RoundTrip(t *testing.T) {
	tenantCR := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha"},
		Spec: wardenio.TenantSpec{
			Policies: []api.PolicyRule{
				{
					Name:    "allow-github",
					Host:    "api.github.com",
					Path:    "/repos/acme/**",
					Methods: []string{"GET", "POST"},
					Action:  "allow",
					Inject: &api.InjectConfig{
						Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"},
					},
				},
				{
					Name:   "deny-metadata",
					Host:   "169.254.169.254",
					Action: "deny",
				},
			},
			Secrets: []api.SecretConfig{
				{Type: "env"},
			},
		},
	}

	yamlStr, err := serializeTenantConfig(tenantCR)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	tc, err := tenant.ParseTenantConfig([]byte(yamlStr))
	if err != nil {
		t.Fatalf("ParseTenantConfig failed on operator-produced YAML: %v\nYAML:\n%s", err, yamlStr)
	}

	if len(tc.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(tc.Policies))
	}

	p := tc.Policies[0]
	if p.Name != "allow-github" {
		t.Errorf("policy name = %q, want allow-github", p.Name)
	}
	if p.Host != "api.github.com" {
		t.Errorf("host = %q", p.Host)
	}
	if p.Path != "/repos/acme/**" {
		t.Errorf("path = %q", p.Path)
	}
	if len(p.Methods) != 2 || p.Methods[0] != "GET" || p.Methods[1] != "POST" {
		t.Errorf("methods = %v", p.Methods)
	}
	if p.Action != "allow" {
		t.Errorf("action = %q", p.Action)
	}
	if p.Inject == nil || p.Inject.Headers["Authorization"] != "Bearer ${TOKEN}" {
		t.Errorf("inject = %+v", p.Inject)
	}

	if tc.Policies[1].Action != "deny" {
		t.Errorf("second policy action = %q, want deny", tc.Policies[1].Action)
	}

	if len(tc.Secrets) != 1 || tc.Secrets[0].Type != "env" {
		t.Errorf("secrets = %+v", tc.Secrets)
	}
}

func TestSerializeTenantConfig_EmptySecrets(t *testing.T) {
	tenantCR := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "minimal"},
		Spec: wardenio.TenantSpec{
			Policies: []api.PolicyRule{
				{Name: "allow-all", Host: "*.example.com", Action: "allow"},
			},
		},
	}

	yamlStr, err := serializeTenantConfig(tenantCR)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	tc, err := tenant.ParseTenantConfig([]byte(yamlStr))
	if err != nil {
		t.Fatalf("ParseTenantConfig: %v\nYAML:\n%s", err, yamlStr)
	}

	if len(tc.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(tc.Policies))
	}
}

func TestSerializeTenantConfig_VaultSecret(t *testing.T) {
	tenantCR := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-tenant"},
		Spec: wardenio.TenantSpec{
			Policies: []api.PolicyRule{
				{Name: "allow", Host: "api.example.com", Action: "allow"},
			},
			Secrets: []api.SecretConfig{
				{
					Type: "vault",
					Vault: api.VaultSecretConfig{
						Address: "https://vault.example.com",
						Mount:   "secret",
						Auth:    "kubernetes",
					},
				},
			},
		},
	}

	yamlStr, err := serializeTenantConfig(tenantCR)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	tc, err := tenant.ParseTenantConfig([]byte(yamlStr))
	if err != nil {
		t.Fatalf("ParseTenantConfig: %v\nYAML:\n%s", err, yamlStr)
	}

	if len(tc.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(tc.Secrets))
	}
	if tc.Secrets[0].Type != "vault" {
		t.Errorf("type = %q", tc.Secrets[0].Type)
	}
	if tc.Secrets[0].Vault.Address != "https://vault.example.com" {
		t.Errorf("address = %q", tc.Secrets[0].Vault.Address)
	}
}

func TestSerializeTenantConfig_InjectQuery(t *testing.T) {
	tenantCR := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "query-inject"},
		Spec: wardenio.TenantSpec{
			Policies: []api.PolicyRule{
				{
					Name:   "with-query",
					Host:   "api.example.com",
					Action: "allow",
					Inject: &api.InjectConfig{
						Query: map[string]string{"api_key": "${API_KEY}"},
					},
				},
			},
			Secrets: []api.SecretConfig{{Type: "env"}},
		},
	}

	yamlStr, err := serializeTenantConfig(tenantCR)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	tc, err := tenant.ParseTenantConfig([]byte(yamlStr))
	if err != nil {
		t.Fatalf("ParseTenantConfig: %v\nYAML:\n%s", err, yamlStr)
	}

	if tc.Policies[0].Inject == nil {
		t.Fatal("inject is nil")
	}
	if tc.Policies[0].Inject.Query["api_key"] != "${API_KEY}" {
		t.Errorf("query = %v", tc.Policies[0].Inject.Query)
	}
}

func FuzzSerializeTenantConfig(f *testing.F) {
	f.Add("test-policy", "*.example.com", "/api/**", "allow", "env")
	f.Add("deny-meta", "169.254.169.254", "/**", "deny", "")
	f.Add("special-chars", "api.example.com", "/path/with spaces", "allow", "vault")

	f.Fuzz(func(t *testing.T, name, host, path, action, secretType string) {
		if name == "" || host == "" || action == "" {
			return
		}
		if action != "allow" && action != "deny" {
			return
		}

		tenantCR := &wardenio.Tenant{
			ObjectMeta: metav1.ObjectMeta{Name: "fuzz"},
			Spec: wardenio.TenantSpec{
				Policies: []api.PolicyRule{
					{Name: name, Host: host, Path: path, Action: action},
				},
			},
		}

		if secretType == "env" || secretType == "file" || secretType == "vault" || secretType == "kubernetes" {
			tenantCR.Spec.Secrets = []api.SecretConfig{{Type: secretType}}
		}

		yamlStr, err := serializeTenantConfig(tenantCR)
		if err != nil {
			return
		}

		_, err = tenant.ParseTenantConfig([]byte(yamlStr))
		if err != nil {
			t.Errorf("round-trip failed: serialize succeeded but parse failed: %v\nYAML:\n%s", err, yamlStr)
		}
	})
}
