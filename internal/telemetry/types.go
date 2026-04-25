package telemetry

import "context"

type TelemetryExporter interface {
	LogRequest(ctx context.Context, entry RequestLog) error
	StartSpan(ctx context.Context, name string, attrs ...SpanAttr) (context.Context, SpanHandle)
	RecordMetric(ctx context.Context, name string, value float64, attrs ...MetricAttr)
	Close(ctx context.Context) error
}

type SpanHandle interface {
	End()
	SetStatus(code int, msg string)
	AddAttr(key string, value any)
}

type SpanAttr struct {
	Key   string
	Value string
}

type MetricAttr struct {
	Key   string
	Value string
}

type RequestLog struct {
	ClientIP        string
	Host            string
	Method          string
	Path            string
	Policy          string
	Action          string
	Reason          string
	InjectedSecrets []string
	UpstreamStatus  int
	DurationMs      int64
}
