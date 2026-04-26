package telemetry

import (
	"context"
	"log/slog"
)

type SlogExporter struct {
	logger *slog.Logger
}

func NewSlogExporter(logger *slog.Logger) *SlogExporter {
	return &SlogExporter{logger: logger}
}

func (e *SlogExporter) LogRequest(ctx context.Context, entry RequestLog) error {
	level := slog.LevelInfo
	if entry.Action == "deny" {
		level = slog.LevelWarn
	}

	attrs := []slog.Attr{}

	if entry.TenantID != "" {
		attrs = append(attrs, slog.String("tenant_id", entry.TenantID))
	}

	attrs = append(attrs,
		slog.String("client_ip", entry.ClientIP),
		slog.String("host", entry.Host),
		slog.String("method", entry.Method),
		slog.String("path", entry.Path),
		slog.String("action", entry.Action),
		slog.Int64("duration_ms", entry.DurationMs),
	)

	if entry.Policy != "" {
		attrs = append(attrs, slog.String("policy", entry.Policy))
	}
	if entry.Reason != "" {
		attrs = append(attrs, slog.String("reason", entry.Reason))
	}
	if len(entry.InjectedSecrets) > 0 {
		attrs = append(attrs, slog.Any("injected_secrets", entry.InjectedSecrets))
	}
	if entry.UpstreamStatus > 0 {
		attrs = append(attrs, slog.Int("upstream_status", entry.UpstreamStatus))
	}

	e.logger.LogAttrs(ctx, level, "request", attrs...)
	return nil
}

type NoopSpan struct{}

func (NoopSpan) End()                  {}
func (NoopSpan) SetStatus(int, string) {}
func (NoopSpan) AddAttr(string, any)   {}

func (e *SlogExporter) StartSpan(ctx context.Context, _ string, _ ...SpanAttr) (context.Context, SpanHandle) {
	return ctx, NoopSpan{}
}

func (e *SlogExporter) RecordMetric(_ context.Context, _ string, _ float64, _ ...MetricAttr) {}

func (e *SlogExporter) Close(_ context.Context) error { return nil }
