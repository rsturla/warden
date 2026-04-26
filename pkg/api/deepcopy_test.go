package api

import "testing"

func TestPolicyRuleDeepCopyIntercept(t *testing.T) {
	orig := &PolicyRule{
		Name:   "test",
		Host:   "example.com",
		Action: "allow",
		Intercept: &InterceptConfig{
			Credential: "TOKEN",
		},
	}

	cp := orig.DeepCopy()

	if cp.Intercept == nil {
		t.Fatal("Intercept should be deep copied")
	}
	if cp.Intercept == orig.Intercept {
		t.Error("Intercept should be a separate pointer")
	}
	if cp.Intercept.Credential != "TOKEN" {
		t.Errorf("Credential = %q", cp.Intercept.Credential)
	}

	cp.Intercept.Credential = "CHANGED"
	if orig.Intercept.Credential != "TOKEN" {
		t.Error("mutation leaked to original")
	}
}

func TestPolicyRuleDeepCopyNilIntercept(t *testing.T) {
	orig := &PolicyRule{
		Name:   "test",
		Host:   "example.com",
		Action: "allow",
	}
	cp := orig.DeepCopy()
	if cp.Intercept != nil {
		t.Error("nil Intercept should stay nil")
	}
}

func TestPolicyRuleDeepCopyNil(t *testing.T) {
	var orig *PolicyRule
	if orig.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

func TestPolicyRuleDeepCopyInject(t *testing.T) {
	orig := &PolicyRule{
		Name:   "test",
		Host:   "example.com",
		Action: "allow",
		Inject: &InjectConfig{
			Headers: map[string]string{"Authorization": "Bearer tok"},
			Query:   map[string]string{"key": "val"},
		},
	}

	cp := orig.DeepCopy()

	if cp.Inject == orig.Inject {
		t.Error("Inject should be a separate pointer")
	}
	cp.Inject.Headers["Authorization"] = "CHANGED"
	if orig.Inject.Headers["Authorization"] != "Bearer tok" {
		t.Error("header mutation leaked to original")
	}
	cp.Inject.Query["key"] = "CHANGED"
	if orig.Inject.Query["key"] != "val" {
		t.Error("query mutation leaked to original")
	}
}

func TestPolicyRuleDeepCopyMethods(t *testing.T) {
	orig := &PolicyRule{
		Name:    "test",
		Host:    "example.com",
		Action:  "allow",
		Methods: []string{"GET", "POST"},
	}

	cp := orig.DeepCopy()
	cp.Methods[0] = "DELETE"
	if orig.Methods[0] != "GET" {
		t.Error("methods mutation leaked to original")
	}
}

func TestSecretConfigDeepCopyGCPScopes(t *testing.T) {
	orig := &SecretConfig{
		Type: "gcp-service-account",
		GCP: GCPSecretConfig{
			CredentialsFile: "/path/key.json",
			Scopes:          []string{"scope1", "scope2"},
			TokenName:       "TOK",
		},
	}

	cp := orig.DeepCopy()

	if cp.GCP.CredentialsFile != "/path/key.json" {
		t.Errorf("CredentialsFile = %q", cp.GCP.CredentialsFile)
	}
	if len(cp.GCP.Scopes) != 2 {
		t.Fatalf("Scopes len = %d", len(cp.GCP.Scopes))
	}

	cp.GCP.Scopes[0] = "CHANGED"
	if orig.GCP.Scopes[0] != "scope1" {
		t.Error("scopes mutation leaked to original")
	}
}

func TestSecretConfigDeepCopyNilScopes(t *testing.T) {
	orig := &SecretConfig{
		Type: "gcp-service-account",
		GCP: GCPSecretConfig{
			CredentialsFile: "/path/key.json",
		},
	}
	cp := orig.DeepCopy()
	if cp.GCP.Scopes != nil {
		t.Error("nil scopes should stay nil")
	}
}

func TestSecretConfigDeepCopyNil(t *testing.T) {
	var orig *SecretConfig
	if orig.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

func TestTenantConfigDeepCopy(t *testing.T) {
	orig := &TenantConfig{
		Policies: []PolicyRule{
			{
				Name: "p1", Host: "h", Action: "allow",
				Methods:   []string{"GET"},
				Intercept: &InterceptConfig{Credential: "TOK"},
			},
		},
		Secrets: []SecretConfig{
			{Type: "env"},
		},
	}

	var cp TenantConfig
	orig.DeepCopyInto(&cp)

	cp.Policies[0].Methods[0] = "DELETE"
	if orig.Policies[0].Methods[0] != "GET" {
		t.Error("policy methods mutation leaked")
	}

	cp.Policies[0].Intercept.Credential = "CHANGED"
	if orig.Policies[0].Intercept.Credential != "TOK" {
		t.Error("intercept mutation leaked")
	}
}
