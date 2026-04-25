package policy

import (
	"context"
	"testing"

	"github.com/rsturla/warden/internal/config"
)

func BenchmarkPolicyEvaluate(b *testing.B) {
	rules := []config.PolicyRule{
		{Name: "block-metadata", Host: "169.254.169.254", Path: "/**", Action: "deny"},
		{Name: "block-localhost", Host: "localhost", Path: "/**", Action: "deny"},
		{Name: "github-read", Host: "api.github.com", Path: "/repos/myorg/**", Methods: []string{"GET"}, Action: "allow"},
		{Name: "github-write", Host: "api.github.com", Path: "/repos/myorg/*/pulls", Methods: []string{"POST"}, Action: "allow"},
		{Name: "pypi", Host: "pypi.org", Path: "/**", Methods: []string{"GET"}, Action: "allow"},
	}
	engine, _ := NewYAMLPolicyEngine(rules)
	ctx := context.Background()

	req := &RequestContext{Host: "api.github.com", Path: "/repos/myorg/app/src/main.go", Method: "GET"}

	for b.Loop() {
		engine.Evaluate(ctx, req)
	}
}

func BenchmarkPolicyEvaluateNoMatch(b *testing.B) {
	rules := []config.PolicyRule{
		{Name: "github", Host: "api.github.com", Path: "/repos/**", Action: "allow"},
		{Name: "pypi", Host: "pypi.org", Path: "/**", Action: "allow"},
	}
	engine, _ := NewYAMLPolicyEngine(rules)
	ctx := context.Background()

	req := &RequestContext{Host: "evil.com", Path: "/steal", Method: "POST"}

	for b.Loop() {
		engine.Evaluate(ctx, req)
	}
}

func BenchmarkPathGlobMatch(b *testing.B) {
	fn, _ := CompilePathGlob("/repos/*/issues/**")
	for b.Loop() {
		fn("/repos/myorg/issues/123/comments")
	}
}
