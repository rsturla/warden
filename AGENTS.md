# Warden — Agent Guide

MITM proxy for policy-based access control and secret injection for agentic workloads. Go 1.26.

## Quick Reference

```bash
make              # full pipeline: deps → lint → test → build
make build        # dev build with version injection
make release      # release build: stripped, static, CGO_ENABLED=0
make test         # all tests
make test-race    # with race detector (CI default)
make fuzz         # 10 fuzz targets, FUZZ_TIME=30s, parallel
make lint         # go vet + staticcheck
make coverage     # HTML coverage report
make bench        # benchmarks on hot paths
make run          # build + run (CONFIG=config.example.yaml)
make deps-update  # update all deps to latest
```

## Module

`github.com/rsturla/warden` — 3 external deps (`go.yaml.in/yaml/v3`, `github.com/mdlayher/vsock`, `golang.org/x/sync`). Everything else is stdlib.

## Project Structure

```
cmd/warden/              main proxy binary
cmd/warden-bridge/       vsock-to-TCP bridge for guest VMs
internal/
  ca/                    TLS CA, auto-gen or external, per-host cert cache
  config/                YAML config types, parsing, validation, defaults
  dns/                   resolver (stdlib wrapper), TTL cache, IP denylist
  health/                /healthz + /readyz on separate port
  inject/                header/query injection, ${VAR} template resolution
  listener/              TCP + vsock listener factory, connection limiter
  policy/                PolicyEngine interface, host/path glob, first-match-wins
  proxy/                 HTTP forward proxy + HTTPS CONNECT MITM handler
  secrets/               SecretSource interface, env + file implementations
  telemetry/             TelemetryExporter interface, slog JSON implementation
  version/               version/commit/date vars (injected via ldflags)
```

## Key Interfaces

All interfaces take `context.Context` as first parameter.

**PolicyEngine** (`internal/policy/types.go`):
- `Evaluate(ctx, *RequestContext) (*PolicyDecision, error)` — first-match-wins, default-deny
- `CanMatchHost(host string) bool` — early CONNECT rejection before TLS handshake

**SecretSource** (`internal/secrets/source.go`):
- `Resolve(ctx, name string) (string, bool, error)` — resolve variable by name
- Implementations: `EnvSource`, `FileSource` (uses `os.Root` for path traversal safety)

**TelemetryExporter** (`internal/telemetry/types.go`):
- `LogRequest(ctx, RequestLog) error` — log every proxied request
- Implementation: `SlogExporter` using `log/slog` with `slog.JSONHandler`

## Request Flow

1. Listener accepts connection (TCP or vsock)
2. HTTP: policy eval → inject → forward. HTTPS: `CanMatchHost` → fast 403 if no allow rule
3. HTTPS CONNECT: hijack → TLS handshake (dynamic cert from CA) → decrypt → policy eval → inject → re-encrypt → forward
4. Secret values never logged — telemetry only sees variable names

## Code Conventions

- **All interactions through Make** — never run `go` commands directly
- **log/slog** for all logging — `slog.NewJSONHandler(os.Stdout, nil)`
- **Default-deny** — no matching policy = 403 Forbidden
- **Fail-closed** — secret resolution failure = 403, not forward without auth
- **No comments unless WHY is non-obvious** — code should be self-documenting
- **Errors**: return as last value, wrap with `fmt.Errorf("context: %w", err)` at boundaries
- **No panics** in library code
- **ECDSA P-256** for all generated keys — `PrivateKey.Bytes()` not big.Int fields (deprecated in Go 1.25)
- **os.Root** for file access — prevents path traversal by design
- **net/http ServeMux patterns** (`GET /healthz`) for routing

## Testing

- Every package has `_test.go` files — unit, integration, and fuzz
- **Fuzz targets** on all input-parsing surfaces (10 targets): globs, templates, config, certs, IPs, headers, requests
- **Race detector** required in CI (`make test-race`)
- **Benchmarks** on policy eval (~118ns/op), CA cert gen, DNS, secret resolution
- Test helpers use `t.Helper()`, `t.TempDir()`, `t.Setenv()`
- Proxy integration tests use `httptest.NewServer` / `httptest.NewTLSServer`
- Concurrent tests use `sync.WaitGroup`, `atomic`, channels

## Build & Release

- `make build` — dev build, includes `-ldflags` for version/commit/date
- `make release` — production: `CGO_ENABLED=0`, `-trimpath`, `-s -w` (stripped)
- Version from `git describe --tags --always --dirty`
- `./bin/warden --version` prints version info

## Adding New Features

**New secret backend:** implement `SecretSource` in `internal/secrets/`, register type string in `internal/config/config.go` validation, wire in `cmd/warden/main.go`.

**New policy engine:** implement `PolicyEngine` interface (both `Evaluate` and `CanMatchHost`), swap in `cmd/warden/main.go`.

**New telemetry backend:** implement `TelemetryExporter` in `internal/telemetry/`, wire in `cmd/warden/main.go`.
