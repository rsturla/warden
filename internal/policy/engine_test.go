package policy

import (
	"context"
	"testing"

	"github.com/rsturla/warden/internal/config"
)

func testEngine(t *testing.T, rules []config.PolicyRule) *YAMLPolicyEngine {
	t.Helper()
	e, err := NewYAMLPolicyEngine(rules)
	if err != nil {
		t.Fatalf("NewYAMLPolicyEngine: %v", err)
	}
	return e
}

func TestFirstMatchWinsDenyBeforeAllow(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "deny-admin", Host: "api.github.com", Path: "/orgs/*/members", Action: "deny"},
		{Name: "allow-all", Host: "api.github.com", Path: "/**", Action: "allow"},
	})

	d, err := e.Evaluate(context.Background(), &RequestContext{
		Host: "api.github.com", Path: "/orgs/myorg/members", Method: "GET",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Error("should be denied")
	}
	if d.RuleName != "deny-admin" {
		t.Errorf("rule = %q, want %q", d.RuleName, "deny-admin")
	}
	if d.Reason != "explicit_deny" {
		t.Errorf("reason = %q, want %q", d.Reason, "explicit_deny")
	}
}

func TestFirstMatchWinsAllowBeforeDeny(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "allow-all", Host: "api.github.com", Path: "/**", Action: "allow"},
		{Name: "deny-admin", Host: "api.github.com", Path: "/orgs/*/members", Action: "deny"},
	})

	d, _ := e.Evaluate(context.Background(), &RequestContext{
		Host: "api.github.com", Path: "/orgs/myorg/members", Method: "GET",
	})
	if !d.Allowed {
		t.Error("should be allowed (first match wins)")
	}
	if d.RuleName != "allow-all" {
		t.Errorf("rule = %q", d.RuleName)
	}
}

func TestNoMatchDefaultDeny(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "allow-github", Host: "api.github.com", Path: "/**", Action: "allow"},
	})

	d, _ := e.Evaluate(context.Background(), &RequestContext{
		Host: "evil.com", Path: "/", Method: "GET",
	})
	if d.Allowed {
		t.Error("should be denied (no match)")
	}
	if d.RuleName != "" {
		t.Errorf("rule should be empty, got %q", d.RuleName)
	}
	if d.Reason != "no_match" {
		t.Errorf("reason = %q, want %q", d.Reason, "no_match")
	}
}

func TestEmptyPoliciesDenyAll(t *testing.T) {
	e := testEngine(t, nil)
	d, _ := e.Evaluate(context.Background(), &RequestContext{
		Host: "anything.com", Path: "/", Method: "GET",
	})
	if d.Allowed {
		t.Error("empty policies should deny everything")
	}
}

func TestMethodFiltering(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "get-only", Host: "api.github.com", Path: "/**", Methods: []string{"GET"}, Action: "allow"},
	})

	d, _ := e.Evaluate(context.Background(), &RequestContext{
		Host: "api.github.com", Path: "/repos", Method: "GET",
	})
	if !d.Allowed {
		t.Error("GET should be allowed")
	}

	d, _ = e.Evaluate(context.Background(), &RequestContext{
		Host: "api.github.com", Path: "/repos", Method: "POST",
	})
	if d.Allowed {
		t.Error("POST should be denied")
	}
}

func TestMethodOmittedMatchesAll(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "all-methods", Host: "api.github.com", Path: "/**", Action: "allow"},
	})

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"} {
		d, _ := e.Evaluate(context.Background(), &RequestContext{
			Host: "api.github.com", Path: "/repos", Method: method,
		})
		if !d.Allowed {
			t.Errorf("%s should be allowed", method)
		}
	}
}

func TestAllowWithInjection(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{
			Name: "with-inject", Host: "api.github.com", Path: "/**", Action: "allow",
			Inject: &config.InjectConfig{
				Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"},
				Query:   map[string]string{"key": "${API_KEY}"},
			},
		},
	})

	d, _ := e.Evaluate(context.Background(), &RequestContext{
		Host: "api.github.com", Path: "/repos", Method: "GET",
	})
	if !d.Allowed {
		t.Fatal("should be allowed")
	}
	if d.Inject == nil {
		t.Fatal("inject should not be nil")
	}
	if d.Inject.Headers["Authorization"] != "Bearer ${TOKEN}" {
		t.Errorf("inject header = %q", d.Inject.Headers["Authorization"])
	}
	if d.Inject.Query["key"] != "${API_KEY}" {
		t.Errorf("inject query = %q", d.Inject.Query["key"])
	}
}

func TestAllowWithoutInjection(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "no-inject", Host: "pypi.org", Path: "/**", Action: "allow"},
	})

	d, _ := e.Evaluate(context.Background(), &RequestContext{
		Host: "pypi.org", Path: "/simple", Method: "GET",
	})
	if !d.Allowed {
		t.Fatal("should be allowed")
	}
	if d.Inject != nil {
		t.Error("inject should be nil for rule without inject")
	}
}

func TestHostGlobMatching(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "wildcard", Host: "*.example.com", Path: "/**", Action: "allow"},
	})

	d, _ := e.Evaluate(context.Background(), &RequestContext{
		Host: "api.example.com", Path: "/", Method: "GET",
	})
	if !d.Allowed {
		t.Error("*.example.com should match api.example.com")
	}

	d, _ = e.Evaluate(context.Background(), &RequestContext{
		Host: "example.com", Path: "/", Method: "GET",
	})
	if d.Allowed {
		t.Error("*.example.com should not match example.com")
	}
}

func TestMultiplePoliciesFullFlow(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "block-metadata", Host: "169.254.169.254", Path: "/**", Action: "deny"},
		{Name: "block-localhost", Host: "localhost", Path: "/**", Action: "deny"},
		{Name: "github-read", Host: "api.github.com", Path: "/repos/myorg/**", Methods: []string{"GET"}, Action: "allow",
			Inject: &config.InjectConfig{Headers: map[string]string{"Authorization": "Bearer ${GH}"}}},
		{Name: "pypi", Host: "pypi.org", Path: "/**", Methods: []string{"GET"}, Action: "allow"},
	})

	tests := []struct {
		name    string
		req     RequestContext
		allowed bool
		rule    string
	}{
		{"metadata blocked", RequestContext{"169.254.169.254", "/latest/meta-data", "GET"}, false, "block-metadata"},
		{"localhost blocked", RequestContext{"localhost", "/", "GET"}, false, "block-localhost"},
		{"github read allowed", RequestContext{"api.github.com", "/repos/myorg/app", "GET"}, true, "github-read"},
		{"github post denied", RequestContext{"api.github.com", "/repos/myorg/app", "POST"}, false, ""},
		{"github other org denied", RequestContext{"api.github.com", "/repos/other/app", "GET"}, false, ""},
		{"pypi allowed", RequestContext{"pypi.org", "/simple/requests", "GET"}, true, "pypi"},
		{"pypi post denied", RequestContext{"pypi.org", "/upload", "POST"}, false, ""},
		{"unknown host denied", RequestContext{"evil.com", "/", "GET"}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := e.Evaluate(context.Background(), &tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed != tt.allowed {
				t.Errorf("allowed = %v, want %v", d.Allowed, tt.allowed)
			}
			if d.RuleName != tt.rule {
				t.Errorf("rule = %q, want %q", d.RuleName, tt.rule)
			}
		})
	}
}

func TestCanMatchHost(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "deny-meta", Host: "169.254.169.254", Path: "/**", Action: "deny"},
		{Name: "allow-github", Host: "api.github.com", Path: "/**", Action: "allow"},
		{Name: "allow-wildcard", Host: "*.example.com", Path: "/**", Action: "allow"},
	})

	tests := []struct {
		host string
		want bool
	}{
		{"api.github.com", true},
		{"sub.example.com", true},
		{"169.254.169.254", false}, // only deny rule
		{"evil.com", false},
		{"example.com", false}, // *.example.com doesn't match bare
	}
	for _, tt := range tests {
		got := e.CanMatchHost(tt.host)
		if got != tt.want {
			t.Errorf("CanMatchHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestCanMatchHostNoPolicies(t *testing.T) {
	e := testEngine(t, nil)
	if e.CanMatchHost("anything.com") {
		t.Error("empty engine should never match")
	}
}

func TestCanMatchHostOnlyDeny(t *testing.T) {
	e := testEngine(t, []config.PolicyRule{
		{Name: "deny-all", Host: "example.com", Path: "/**", Action: "deny"},
	})
	if e.CanMatchHost("example.com") {
		t.Error("deny-only should not match for CanMatchHost")
	}
}
