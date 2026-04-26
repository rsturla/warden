# Warden — Agent Guide

MITM proxy for policy-based access control and secret injection for agentic workloads. Go 1.26.

## Quick Reference

```bash
make              # full pipeline: deps → lint → test → build
make build        # dev build with version injection
make release      # release build: stripped, static, CGO_ENABLED=0
make test         # all tests
make test-race    # with race detector (CI default)
make fuzz         # auto-discovers all Fuzz* targets, FUZZ_TIME=30s, parallel
make lint         # go vet + staticcheck
make coverage     # HTML coverage report
make bench        # benchmarks on hot paths
make run          # build + run (CONFIG=config.example.yaml)
make deps-update  # update all deps to latest
```

## Module

`github.com/rsturla/warden` — 3 external deps (`go.yaml.in/yaml/v3`, `github.com/mdlayher/vsock`, `golang.org/x/sync`). Rest stdlib.

## Project Structure

```
cmd/warden/              main proxy binary
cmd/warden-bridge/       vsock-to-TCP bridge for guest VMs
pkg/api/                 shared types (PolicyRule, SecretConfig, TenantConfig)
internal/
  ca/                    TLS CA, auto-gen or external, per-host cert cache
  config/                YAML config types, parsing, validation, defaults
  dns/                   resolver (stdlib/DoT), TTL cache, IP denylist
  health/                /healthz + /readyz on separate port
  inject/                header/query injection, ${VAR} template resolution
  listener/              TCP + vsock listener factory, connection limiter
  policy/                PolicyEngine interface, host/path glob, first-match-wins
  proxy/                 HTTP forward proxy + HTTPS CONNECT MITM handler, TenantResolver
  secrets/               SecretSource interface: env, file, vault, kubernetes, github-app
  telemetry/             TelemetryExporter interface: slog JSON, OTLP/HTTP, multi-exporter
  tenant/                Tenant store interface, per-tenant config, FileStore with hot reload
  version/               version/commit/date vars (injected via ldflags)
operator/                Kubernetes operator (separate Go module, see operator/CLAUDE.md)
  api/v1alpha1/          CRD types: Tenant, WardenProxy (wardenproxy.dev/v1alpha1)
  cmd/operator/          controller-manager entrypoint
  internal/controller/   reconcilers (Tenant → ConfigMap, WardenProxy → Deployment)
  internal/webhook/      mutating webhook (injects warden-bridge sidecar)
```

## Key Interfaces

All interfaces take `context.Context` first param. See [Development](docs/development.md) for full signatures.

- **TenantResolver** — `Resolve(r *http.Request) (*resolvedTenant, error)`. All policy/secret access goes through this. Implementations: SingleTenantResolver, MTLSTenantResolver.
- **PolicyEngine** — `Evaluate` (first-match-wins, default-deny) + `CanMatchHost` (early CONNECT rejection)
- **SecretSource** — `Resolve(ctx, name) (string, bool, error)`. Implementations: env, file, vault, kubernetes, github-app. See [Secrets](docs/secrets.md).
- **TelemetryExporter** — `LogRequest`, `StartSpan`, `RecordMetric`, `Close`. Implementations: slog, OTLP/HTTP, multi. See [Telemetry](docs/telemetry.md).
- **Tenant Store** — `Get(ctx, tenantID)` + `List(ctx)` + `Close()`. Implementation: FileStore (directory of YAML files, hot reload).

## Request Flow

1. Listener accepts connection (TCP or vsock)
2. HTTP: policy eval → inject → forward. HTTPS: `CanMatchHost` → fast 403 if no allow rule
3. HTTPS CONNECT: hijack → TLS handshake (dynamic cert from CA) → decrypt → policy eval → inject → re-encrypt → forward
4. Secret values never logged — telemetry only sees variable names

## Code Conventions

- **All interactions through Make** — never run `go` commands direct
- **Default-deny** / **fail-closed** — no match = 403, secret failure = 403
- **No comments unless WHY non-obvious**
- **Errors**: wrap with `fmt.Errorf("context: %w", err)` at boundaries
- **No panics** in library code
- **ECDSA P-256** for generated keys, **os.Root** for file access
- **log/slog** for logging, **net/http ServeMux patterns** for routing

## Testing

- Every package has `_test.go` files — unit, integration, fuzz
- **Fuzz targets** auto-discovered by `make fuzz` (grep for `func Fuzz*` in `*_test.go`)
- **Race detector** required in CI (`make test-race`)
- Test helpers use `t.Helper()`, `t.TempDir()`, `t.Setenv()`
- Proxy integration tests use `httptest.NewServer` / `httptest.NewTLSServer`

## Documentation

Full documentation lives in [`docs/`](docs/):

- [Configuration](docs/configuration.md) — full config reference, defaults, validation
- [Policies](docs/policies.md) — rules, globs, evaluation order, injection
- [Secrets](docs/secrets.md) — all backend types with examples
- [Telemetry](docs/telemetry.md) — logs, traces, metrics, OTLP
- [DNS](docs/dns.md) — resolution, DoT, caching, IP denylist
- [Deployment](docs/deployment.md) — container, microVM, agent trust, operator
- [Development](docs/development.md) — building, testing, extending
- [Local Testing](docs/local-testing.md) — kind cluster, Agent Sandbox, e2e tests
- [Operator](operator/CLAUDE.md) — CRDs, controllers, webhook (separate Go module)
