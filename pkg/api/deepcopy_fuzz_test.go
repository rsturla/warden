package api

import "testing"

func FuzzPolicyRuleDeepCopy(f *testing.F) {
	f.Add("test", "example.com", "/api", "allow", "TOKEN", true)
	f.Add("deny-rule", "*.evil.com", "/**", "deny", "", false)
	f.Add("", "", "", "", "", false)

	f.Fuzz(func(t *testing.T, name, host, path, action, credential string, hasIntercept bool) {
		orig := PolicyRule{
			Name:    name,
			Host:    host,
			Path:    path,
			Action:  action,
			Methods: []string{"GET", "POST"},
		}
		if hasIntercept && credential != "" {
			orig.Intercept = &InterceptConfig{Credential: credential}
		}

		cp := orig.DeepCopy()
		if cp == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if cp.Name != orig.Name || cp.Host != orig.Host {
			t.Error("field mismatch")
		}

		if orig.Intercept != nil {
			if cp.Intercept == nil {
				t.Fatal("Intercept lost in copy")
			}
			if cp.Intercept.Credential != orig.Intercept.Credential {
				t.Error("Credential mismatch")
			}
		}

		if len(cp.Methods) > 0 {
			cp.Methods[0] = "MUTATED"
			if orig.Methods[0] == "MUTATED" {
				t.Error("methods share backing array")
			}
		}
	})
}

func FuzzSecretConfigDeepCopy(f *testing.F) {
	f.Add("gcp-service-account", "/key.json", "scope1", "TOK")
	f.Add("env", "", "", "")
	f.Add("vault", "", "", "")

	f.Fuzz(func(t *testing.T, typ, credFile, scope, tokenName string) {
		orig := SecretConfig{
			Type: typ,
			GCP: GCPSecretConfig{
				CredentialsFile: credFile,
				TokenName:       tokenName,
			},
		}
		if scope != "" {
			orig.GCP.Scopes = []string{scope}
		}

		cp := orig.DeepCopy()
		if cp == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if cp.Type != orig.Type {
			t.Error("Type mismatch")
		}

		if orig.GCP.Scopes != nil {
			if cp.GCP.Scopes == nil {
				t.Fatal("Scopes lost in copy")
			}
			cp.GCP.Scopes[0] = "MUTATED"
			if orig.GCP.Scopes[0] == "MUTATED" {
				t.Error("scopes share backing array")
			}
		}
	})
}
