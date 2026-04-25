package inject

import (
	"context"
	"net/http"
	"testing"

	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

type stubSource struct {
	values map[string]string
}

func (s *stubSource) Name() string { return "stub" }
func (s *stubSource) Resolve(_ context.Context, name string) (string, bool, error) {
	v, ok := s.values[name]
	return v, ok, nil
}

func chain() *secrets.Chain {
	return secrets.NewChain(&stubSource{map[string]string{
		"TOKEN":   "ghp_secret",
		"API_KEY": "key123",
	}})
}

func TestApplyHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos", nil)
	result, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer ghp_secret" {
		t.Errorf("header = %q", req.Header.Get("Authorization"))
	}
	if len(result.InjectedSecretNames) != 1 || result.InjectedSecretNames[0] != "TOKEN" {
		t.Errorf("names = %v", result.InjectedSecretNames)
	}
}

func TestApplyHeadersOverwrite(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos", nil)
	req.Header.Set("Authorization", "agent-supplied-garbage")

	_, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer ghp_secret" {
		t.Errorf("header not overwritten: %q", req.Header.Get("Authorization"))
	}
}

func TestApplyMultipleHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	_, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Headers: map[string]string{
			"Authorization": "Bearer ${TOKEN}",
			"X-API-Key":     "${API_KEY}",
		},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer ghp_secret" {
		t.Errorf("auth = %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-API-Key") != "key123" {
		t.Errorf("api-key = %q", req.Header.Get("X-API-Key"))
	}
}

func TestApplyQuery(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/data?existing=yes", nil)
	_, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Query: map[string]string{"api_key": "${API_KEY}"},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Query().Get("api_key") != "key123" {
		t.Errorf("query = %q", req.URL.Query().Get("api_key"))
	}
	if req.URL.Query().Get("existing") != "yes" {
		t.Error("existing query param should be preserved")
	}
}

func TestApplyQueryOverwrite(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/?api_key=agent-supplied", nil)
	_, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Query: map[string]string{"api_key": "${API_KEY}"},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Query().Get("api_key") != "key123" {
		t.Errorf("query not overwritten: %q", req.URL.Query().Get("api_key"))
	}
}

func TestApplyQueryNoExisting(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	_, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Query: map[string]string{"key": "static-value"},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Query().Get("key") != "static-value" {
		t.Errorf("query = %q", req.URL.Query().Get("key"))
	}
}

func TestApplyBothHeadersAndQuery(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	result, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"},
		Query:   map[string]string{"key": "${API_KEY}"},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer ghp_secret" {
		t.Error("header missing")
	}
	if req.URL.Query().Get("key") != "key123" {
		t.Error("query missing")
	}
	if len(result.InjectedSecretNames) != 2 {
		t.Errorf("expected 2 names, got %v", result.InjectedSecretNames)
	}
}

func TestApplyStaticValues(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	result, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Headers: map[string]string{"X-Custom": "static"},
	}, chain())
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Custom") != "static" {
		t.Errorf("header = %q", req.Header.Get("X-Custom"))
	}
	if len(result.InjectedSecretNames) != 0 {
		t.Errorf("no secret names expected, got %v", result.InjectedSecretNames)
	}
}

func TestApplyNilDirective(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	result, err := Apply(context.Background(), req, nil, chain())
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("nil directive should return nil result")
	}
}

func TestApplySecretResolutionFailure(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	_, err := Apply(context.Background(), req, &policy.InjectionDirective{
		Headers: map[string]string{"Authorization": "Bearer ${MISSING}"},
	}, chain())
	if err == nil {
		t.Error("expected error for missing secret")
	}
}
