# Telemetry

Warden exports three telemetry signals: logs, traces, and metrics. The telemetry system is interface-driven, supporting multiple exporters simultaneously via a fan-out `MultiExporter`.

## Configuration

```yaml
telemetry:
  logs:
    level: info              # info, warn, error
    format: json             # json only
  traces:
    enabled: true
    endpoint: "http://otel-collector:4317"
  metrics:
    enabled: true
    endpoint: "http://otel-collector:4317"
```

When traces or metrics are enabled, Warden runs both the structured log exporter (`SlogExporter`) and the OTLP exporter (`OTELExporter`) simultaneously via `MultiExporter`.

## Logs

Structured JSON via Go's `log/slog`. Always active regardless of traces/metrics configuration.

Every proxied request produces a log entry:

```json
{
  "time": "2026-04-25T12:00:00Z",
  "level": "INFO",
  "msg": "request",
  "tenant_id": "agent-alpha",
  "client_ip": "10.0.0.5",
  "host": "api.github.com",
  "method": "GET",
  "path": "/repos/myorg/app/pulls",
  "policy": "github-api",
  "action": "allow",
  "injected_secrets": ["GITHUB_TOKEN"],
  "upstream_status": 200,
  "duration_ms": 142
}
```

Denied requests log at `WARN` level and include a `reason` field (`no_match` or the deny rule name). Fields with empty/zero values are omitted. The `tenant_id` field is present in multi-tenant mode and empty in single-tenant mode.

**Secret values are never logged.** Only variable names appear in `injected_secrets`.

## Traces

OTLP/HTTP JSON export. No protobuf dependencies — Warden implements the OTLP JSON wire format directly with stdlib.

Every proxied request generates a root span `warden.proxy` with attributes:

| Attribute | Description |
|-----------|-------------|
| `http.method` | Request method |
| `http.host` | Target hostname |
| `http.target` | Request path |
| `http.status_code` | Upstream response status (allow only) |
| `warden.action` | `allow` or `deny` |
| `warden.policy` | Matching policy rule name |
| `warden.tenant_id` | Tenant ID (multi-tenant mode only) |
| `net.peer.ip` | Client IP address |

Denied requests have span status `ERROR` with the denial reason as the message.

### Sub-operation spans

The `TelemetryExporter` interface supports `StartSpan` for instrumenting sub-operations. When implemented in the proxy, these produce child spans:

```
warden.proxy
├── warden.tls_handshake
├── warden.policy_eval
├── warden.secret_resolve      (if inject configured)
├── warden.dns_resolve
└── warden.upstream_request
```

### Span batching

Spans are buffered in memory and flushed:
- Periodically (default: every 10 seconds)
- When the buffer reaches max batch size (default: 512 spans)
- On shutdown (`Close`)

## Metrics

OTLP/HTTP JSON export with cumulative aggregation.

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| `warden.requests.total` | `http.method`, `warden.action`, `warden.tenant_id` | Total proxied requests |
| `warden.requests.denied` | `reason` | Denied requests |

### Histograms

| Metric | Labels | Description |
|--------|--------|-------------|
| `warden.request.duration_ms` | `http.method`, `warden.action` | End-to-end request latency |

Histograms use explicit bucket boundaries: 1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000 ms.

### Metric flushing

Metrics are cumulative and flushed on the same interval as traces. Counters are monotonic; histograms track count, sum, and bucket distributions.

## OTLP Collector Setup

Warden exports to any OTLP-compatible collector. Example with the OpenTelemetry Collector:

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: "0.0.0.0:4317"

exporters:
  # Choose your backend
  jaeger:
    endpoint: "jaeger:14250"
  prometheus:
    endpoint: "0.0.0.0:8889"

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [jaeger]
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
```

Point Warden at the collector:

```yaml
telemetry:
  traces:
    enabled: true
    endpoint: "http://otel-collector:4317"
  metrics:
    enabled: true
    endpoint: "http://otel-collector:4317"
```

## Exporters

### SlogExporter

Always active. Structured JSON logs to stdout. Implements `StartSpan` and `RecordMetric` as no-ops.

### OTELExporter

Enabled when traces or metrics are configured. Exports OTLP/HTTP JSON to the configured endpoints. Handles span context propagation, metric aggregation, and periodic flushing.

### MultiExporter

Composes multiple exporters. All calls fan out to each child exporter. Used internally to run slog and OTLP exporters simultaneously.

## Adding Custom Exporters

Implement the `TelemetryExporter` interface:

```go
type TelemetryExporter interface {
    LogRequest(ctx context.Context, entry RequestLog) error
    StartSpan(ctx context.Context, name string, attrs ...SpanAttr) (context.Context, SpanHandle)
    RecordMetric(ctx context.Context, name string, value float64, attrs ...MetricAttr)
    Close(ctx context.Context) error
}
```

Wire it into `cmd/warden/main.go` via `MultiExporter`. See [Development](development.md).
