# Development

## Prerequisites

- Go 1.26+
- GNU Make

## Build

```bash
make build           # Dev build with version injection
make release         # Production: stripped, static, CGO_ENABLED=0
```

## Test

```bash
make test            # All tests
make test-race       # With race detector (required in CI)
make fuzz            # All fuzz targets, auto-discovered (FUZZ_TIME=30s)
make coverage        # HTML coverage report
make bench           # Benchmarks on hot paths
```

### Fuzz testing

`make fuzz` auto-discovers all `func Fuzz*` functions in `*_test.go` files and runs each for `FUZZ_TIME` (default: 30s) with `FUZZ_PARALLEL` workers (default: `nproc`).

```bash
make fuzz FUZZ_TIME=2m FUZZ_PARALLEL=24
```

Fuzz targets cover input-parsing surfaces: globs, templates, config, certificates, IPs, headers, and proxy requests.

### Running locally

```bash
make run CONFIG=config.example.yaml
```

## All Make Targets

```bash
make help
```

| Target | Description |
|--------|-------------|
| `make` | Full pipeline: deps, lint, test, build |
| `make build` | Build `warden` and `warden-bridge` binaries |
| `make release` | Production build (stripped, static) |
| `make test` | Run all tests |
| `make test-race` | Tests with race detector |
| `make fuzz` | Auto-discover and run all fuzz targets |
| `make lint` | `go vet` + `staticcheck` |
| `make coverage` | Generate HTML coverage report |
| `make bench` | Run benchmarks |
| `make deps-update` | Update all dependencies |
| `make clean` | Remove build artifacts |

## Project Structure

```
cmd/
  warden/              Main proxy server
  warden-bridge/       vsock-to-TCP bridge (runs inside guest VM)
internal/
  ca/                  TLS CA, auto-gen or external, per-host cert cache
  config/              YAML config types, parsing, validation, defaults
  dns/                 Resolver (stdlib/DoT), TTL cache, IP denylist
  health/              /healthz + /readyz on separate port
  inject/              Header/query injection, ${VAR} template resolution
  listener/            TCP + vsock listener factory, connection limiter
  policy/              PolicyEngine interface, host/path glob, first-match-wins
  proxy/               HTTP forward proxy + HTTPS CONNECT MITM handler
  secrets/             SecretSource implementations
  telemetry/           TelemetryExporter implementations
  version/             Version/commit/date vars (injected via ldflags)
```

## Key Interfaces

All interfaces take `context.Context` as the first parameter.

### PolicyEngine

```go
type PolicyEngine interface {
    Evaluate(ctx context.Context, req *RequestContext) (*PolicyDecision, error)
    CanMatchHost(host string) bool
}
```

### SecretSource

```go
type SecretSource interface {
    Name() string
    Resolve(ctx context.Context, name string) (string, bool, error)
}
```

### TelemetryExporter

```go
type TelemetryExporter interface {
    LogRequest(ctx context.Context, entry RequestLog) error
    StartSpan(ctx context.Context, name string, attrs ...SpanAttr) (context.Context, SpanHandle)
    RecordMetric(ctx context.Context, name string, value float64, attrs ...MetricAttr)
    Close(ctx context.Context) error
}
```

## Adding Features

### New secret backend

1. Implement `SecretSource` in `internal/secrets/`
2. Add a type-specific config struct in `internal/config/config.go` (use `yaml:",inline"`)
3. Add the type to `SecretConfig` and the validation switch
4. Wire it in `cmd/warden/main.go`
5. Write tests including a fuzz target if the backend parses untrusted input

### New policy engine

1. Implement `PolicyEngine` (both `Evaluate` and `CanMatchHost`)
2. Swap it in `cmd/warden/main.go`

### New telemetry exporter

1. Implement `TelemetryExporter` in `internal/telemetry/`
2. Wire it in `cmd/warden/main.go` via `MultiExporter`

## Code Conventions

- **All interactions through Make** — don't run `go` commands directly
- **log/slog** for all logging
- **Default-deny** — no matching policy = 403
- **Fail-closed** — secret resolution failure = 403, not forward without auth
- **No comments unless WHY is non-obvious**
- **Errors**: wrap with `fmt.Errorf("context: %w", err)` at boundaries
- **No panics** in library code
- **ECDSA P-256** for all generated keys
- **os.Root** for file access (prevents path traversal)
- **net/http ServeMux patterns** for routing

## Dependencies

Warden uses only 3 external dependencies. Everything else is Go stdlib:

- `go.yaml.in/yaml/v3` — YAML config parsing
- `github.com/mdlayher/vsock` — vsock listener/dialer
- `golang.org/x/sync` — errgroup for concurrent operations

New features should use stdlib where feasible. All current secret backends (vault, kubernetes, github-app), DNS-over-TLS, and the OTLP exporter are implemented with stdlib only.
