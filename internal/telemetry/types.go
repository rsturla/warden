package telemetry

import "context"

type TelemetryExporter interface {
	LogRequest(ctx context.Context, entry RequestLog) error
	Close(ctx context.Context) error
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
