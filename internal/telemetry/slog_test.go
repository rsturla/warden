package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestSlogExporterAllow(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	exp := NewSlogExporter(logger)

	err := exp.LogRequest(context.Background(), RequestLog{
		ClientIP:        "10.0.0.5",
		Host:            "api.github.com",
		Method:          "GET",
		Path:            "/repos/myorg/app",
		Policy:          "github-api",
		Action:          "allow",
		InjectedSecrets: []string{"GITHUB_TOKEN"},
		UpstreamStatus:  200,
		DurationMs:      142,
	})
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if m["level"] != "INFO" {
		t.Errorf("level = %v", m["level"])
	}
	if m["host"] != "api.github.com" {
		t.Errorf("host = %v", m["host"])
	}
	if m["action"] != "allow" {
		t.Errorf("action = %v", m["action"])
	}
	if m["policy"] != "github-api" {
		t.Errorf("policy = %v", m["policy"])
	}
}

func TestSlogExporterDeny(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	exp := NewSlogExporter(logger)

	exp.LogRequest(context.Background(), RequestLog{
		ClientIP:   "10.0.0.5",
		Host:       "evil.com",
		Method:     "GET",
		Path:       "/",
		Action:     "deny",
		Reason:     "no_match",
		DurationMs: 1,
	})

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if m["level"] != "WARN" {
		t.Errorf("deny should log at WARN, got %v", m["level"])
	}
	if m["reason"] != "no_match" {
		t.Errorf("reason = %v", m["reason"])
	}
}

func TestSlogExporterOmitsEmpty(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	exp := NewSlogExporter(logger)

	exp.LogRequest(context.Background(), RequestLog{
		ClientIP:   "10.0.0.5",
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		Action:     "deny",
		Reason:     "no_match",
		DurationMs: 1,
	})

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)

	if _, ok := m["injected_secrets"]; ok {
		t.Error("injected_secrets should not be present when empty")
	}
	if _, ok := m["upstream_status"]; ok {
		t.Error("upstream_status should not be present when 0")
	}
	if _, ok := m["policy"]; ok {
		t.Error("policy should not be present when empty")
	}
}

func TestSlogExporterClose(t *testing.T) {
	exp := NewSlogExporter(slog.Default())
	if err := exp.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
