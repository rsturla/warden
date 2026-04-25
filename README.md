# Warden

A MITM proxy that provides path-based access control over HTTP and HTTPS traffic and transparent secret injection for agentic workloads. For HTTPS, Warden intercepts TLS connections, decrypts requests for policy evaluation, and re-encrypts them before forwarding upstream. HTTP requests are inspected directly. Agents never see or handle secrets directly.

## Problem

AI agents running in sandboxed environments need to access authenticated web services (APIs, registries, internal tools). Giving agents direct access to secrets is a security risk — they can leak, be exfiltrated, or persist beyond the session. Unrestricted network access is equally dangerous.

A traditional HTTPS proxy can only see the destination host via `CONNECT` — it cannot inspect request paths, methods, or headers. This limits policy granularity to host-level allow/deny.

Warden solves this by performing TLS interception:

1. **Deep request inspection** — Warden terminates the agent's TLS connection, decrypts the request, and evaluates it against path-level policies before re-encrypting and forwarding upstream.
2. **Policy-driven secret injection** — Policies can inject headers, query parameters, or other credentials into matching requests. The agent never sees the secret.
3. **Default-deny access control** — All requests are denied unless an explicit allow rule matches. Administrators allowlist specific host + path + method combinations. No catch-all, no fallthrough.

## Architecture

Warden runs as a sidecar — one instance per agent. Each agent gets its own Warden with its own policy configuration. The agent connects to Warden over TCP or vsock depending on the deployment model.

**Container sidecar (Kubernetes):**

```
┌──────────────────────────────────────────────────────┐
│  Pod                                                 │
│                                                      │
│  ┌─────────────┐  TCP     ┌────────────────────────┐ │        ┌──────────────┐
│  │             │────────▶ │        Warden           │ │  TLS   │              │
│  │    Agent    │          │                        │─┼──────▶ │  Upstream    │
│  │  (sandbox)  │          │  Policy ─▶ Inject      │ │        │  Service     │
│  │             │◀────────│         ─▶ Forward     │◀┼──────  │              │
│  └─────────────┘          └────────────────────────┘ │        └──────────────┘
│       │                     │                        │
│  Trusts Warden CA      :9090/healthz                 │
│                                                      │
└──────────────────────────────────────────────────────┘
```

**MicroVM (Firecracker, Cloud Hypervisor, QEMU):**

```
┌─────────────────────┐  vsock   ┌────────────────────────┐        ┌──────────────┐
│  Guest VM            │────────▶│        Warden           │  TLS   │              │
│                     │         │                        │───────▶│  Upstream    │
│  ┌─────────────┐    │         │  Policy ─▶ Inject      │        │  Service     │
│  │    Agent    │    │◀────────│         ─▶ Forward     │◀───────│              │
│  │  (sandbox)  │    │         └────────────────────────┘        └──────────────┘
│  └─────────────┘    │              Host / Sidecar
│       │             │
│  Trusts Warden CA   │
│  HTTP_PROXY=vsock   │
└─────────────────────┘
```

vsock provides a direct communication channel between guest VM and host without requiring network access. The agent in the VM has no network interface — all traffic goes through Warden via vsock.

**HTTPS request flow:**

1. Agent is configured to use Warden as its HTTP/HTTPS proxy and trust Warden's CA certificate
2. Agent sends `CONNECT` to Warden; Warden accepts and presents a dynamically generated certificate for the target host, signed by its CA
3. Agent completes TLS handshake with Warden (believing it's talking to the upstream)
4. Warden decrypts the request and evaluates it against policy rules (host, path, method)
5. If no rule matches → `403 Forbidden` (default deny). If explicit deny rule matches → `403 Forbidden` with rule name.
6. If allowed and policy specifies injections → Warden replaces/adds headers or query parameters
7. Warden opens a real TLS connection to the upstream, forwards the modified request, and relays the response back to the agent

**HTTP request flow:**

1. Agent sends plain HTTP request to Warden as a forward proxy
2. Warden inspects the request directly (no TLS to terminate)
3. Same policy evaluation: default-deny, first match wins, injection if configured
4. Warden forwards to upstream over plain HTTP and relays the response

### Supported protocols

| Protocol | Support | Notes |
|----------|---------|-------|
| HTTP/1.1 | yes | Direct inspection, policy + injection |
| HTTPS | yes | MITM — TLS termination, inspection, re-encryption |
| HTTP/2 | yes | Required for gRPC and modern APIs. Same policy model — path-based matching works with gRPC service/method paths (`/package.Service/Method`) |
| WebSocket | upgrade only | Policy evaluated on the HTTP upgrade request. Auth headers injected on upgrade. Once upgraded, frames pass through without inspection |
| SSH, raw TCP, etc. | no | Not an HTTP protocol. Block at network layer, not Warden's responsibility |

## Concepts

### Policies

Policies are ordered rules evaluated top-to-bottom against the decrypted request. First match wins. No match → deny.

Each rule specifies match criteria and an action. Allow rules can optionally inject headers or query parameters into the request before forwarding.

```yaml
policies:
  # --- Recommended: block access to internal/cloud metadata ---
  - name: block-cloud-metadata
    host: "169.254.169.254"
    action: deny

  - name: block-loopback
    host: "localhost"
    action: deny

  - name: block-loopback-ip
    host: "127.0.0.1"
    action: deny

  # --- Application policies ---
  - name: block-github-admin
    host: "api.github.com"
    path: "/orgs/*/members"
    action: deny

  - name: github-api-read
    host: "api.github.com"
    path: "/repos/myorg/**"
    methods: ["GET"]
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${GITHUB_TOKEN}"

  - name: github-api-write
    host: "api.github.com"
    path: "/repos/myorg/*/pulls"
    methods: ["POST", "PATCH"]
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${GITHUB_TOKEN}"

  - name: pypi-read-only
    host: "pypi.org"
    methods: ["GET"]
    action: allow

  - name: internal-api
    host: "api.internal.example.com"
    path: "/v2/**"
    action: allow
    inject:
      headers:
        X-API-Key: "${INTERNAL_API_KEY}"
      query:
        tenant: "${TENANT_ID}"

  # Everything else is denied implicitly
```

### Match fields

| Field     | Required | Default | Description                          |
|-----------|----------|---------|--------------------------------------|
| `name`    | yes      | —       | Rule identifier (used in logs)       |
| `host`    | yes      | —       | Exact hostname or glob (`*.example.com`) |
| `path`    | no       | `/**`   | Path glob (`*` = one segment, `**` = any depth) |
| `methods` | no       | all     | List of HTTP methods                 |
| `action`  | yes      | —       | `allow` or `deny`                    |

### Injection

Allow rules can include an `inject` block. Warden modifies the decrypted request before re-encrypting and forwarding. The agent never sees injected values.

```yaml
inject:
  headers:                    # Set request headers (replaces if present)
    Authorization: "Bearer ${GITHUB_TOKEN}"
    X-Custom: "static-value"
  query:                      # Set query parameters (replaces if present)
    api_key: "${API_KEY}"
```

Injection **replaces** matching keys. If the agent sends a header or query parameter with the same name, Warden overwrites it with the policy-defined value. This prevents agents from supplying their own credentials.

Values use `${VAR}` syntax. Variables are resolved from secret sources at request time. Static strings work too — no `${}` needed.

### Secret sources

Secret sources define where `${VAR}` references are resolved from. Checked in order; first match wins.

**Built-in sources:**

```yaml
secrets:
  - type: env                            # Environment variables

  - type: file                           # Files: /run/secrets/VAR_NAME → value
    path: /run/secrets
```

**Planned sources** (not in v1, but the interface supports adding them):
- `vault` — HashiCorp Vault
- `kubernetes` — Kubernetes secrets
- `github-app` — Dynamic token lifecycle (JWT signing, installation token exchange, caching, refresh)

All secret sources implement the same Go interface, so new backends can be added without changing the proxy or policy engine. See [Extensibility](#extensibility).

### TLS Interception

Warden operates its own Certificate Authority for MITM. When an agent issues a `CONNECT` request, Warden dynamically generates a certificate for the target host signed by this CA. Generated per-host certificates are cached for the lifetime of the process.

#### CA modes

**Auto-generated (default)** — If no CA is configured, Warden generates a self-signed CA on startup and writes the certificate to a shared path. Best for dev and ephemeral sidecars.

```yaml
ca:
  auto: true
  cert_output: /shared/warden-ca.crt    # agent container mounts this volume
```

**External CA** — Bring your own CA certificate and key. Use when the org controls the root of trust or needs centralized key rotation.

```yaml
ca:
  cert: /etc/warden/ca/warden-ca.crt
  key: /etc/warden/ca/warden-ca.key
```

#### Agent trust setup

The agent must trust Warden's CA certificate. In a sidecar deployment, share the CA cert via a shared volume and add it to the agent's trust store at container start:

```bash
# Add Warden CA to system trust store
cp /shared/warden-ca.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust
```

Or set per-process:

```bash
export SSL_CERT_FILE=/shared/warden-ca.crt
```

### Health Endpoint

Warden exposes health checks on a separate port so agents cannot access them through the proxy.

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness — Warden process is running |
| `GET /readyz` | Readiness — config loaded, CA initialized, secret sources reachable |

```yaml
server:
  health_listen: "0.0.0.0:9090"
```

Kubernetes probe config:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9090
readinessProbe:
  httpGet:
    path: /readyz
    port: 9090
```

### DNS Resolution

Warden resolves DNS for all upstream connections. The agent never performs DNS resolution directly — it sends hostnames to Warden via the proxy protocol, and Warden resolves them.

This prevents:
- **DNS rebinding** — agent tricks DNS into resolving an allowed hostname to a private IP. Warden validates resolved IPs against a configurable denylist of private/internal ranges.
- **Policy bypass via IP** — agent resolves a hostname, then connects to the IP directly. Since Warden resolves, the agent never sees the IP.

```yaml
dns:
  servers:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
  dot:                                    # DNS-over-TLS (optional)
    enabled: false
    server: "1.1.1.1:853"
  cache:
    enabled: true
    max_ttl: 300                          # seconds
  deny_resolved_ips:                      # block upstream connections to these ranges
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"                    # link-local / cloud metadata
    - "127.0.0.0/8"                       # loopback
    - "::1/128"
```

When `deny_resolved_ips` is configured, Warden checks the resolved IP before connecting upstream. If the IP falls within a denied range, the request is rejected — even if the hostname matched an allow policy. This catches DNS rebinding attacks that the hostname-based policy rules cannot.

### Telemetry

Warden exports telemetry via OpenTelemetry (OTLP). All three signals — logs, metrics, traces — are supported. The telemetry exporter is behind an interface, so alternative backends can be added without changing the proxy.

#### Traces

Every proxied request produces a span:

```
warden.proxy
├── warden.tls_handshake
├── warden.policy_eval
├── warden.secret_resolve      (if inject configured)
├── warden.dns_resolve
└── warden.upstream_request
```

Span attributes include: `host`, `path`, `method`, `policy.name`, `policy.action`, `upstream.status_code`. Secret **names** are recorded; secret **values** are never included.

#### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `warden.requests.total` | counter | Total requests, labeled by `host`, `action` (allow/deny), `policy` |
| `warden.requests.denied` | counter | Denied requests, labeled by `host`, `reason` (no_match/explicit_deny) |
| `warden.requests.duration_ms` | histogram | End-to-end latency |
| `warden.upstream.duration_ms` | histogram | Upstream request latency only |
| `warden.tls.handshake_duration_ms` | histogram | TLS handshake time |
| `warden.secrets.resolve_errors` | counter | Secret resolution failures, labeled by `source`, `var` |
| `warden.dns.resolve_duration_ms` | histogram | DNS resolution latency |
| `warden.dns.cache_hits` | counter | DNS cache hit count |
| `warden.dns.denied_ips` | counter | Requests blocked by `deny_resolved_ips`, labeled by `host` |

#### Logs

Structured JSON. Every request logs:

```json
{
  "ts": "2026-04-25T12:00:00Z",
  "level": "info",
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

Denied requests log at `warn` level with `reason` field (`no_match` or `explicit_deny`).

Secret values are **never** logged, traced, or exported in any telemetry signal.

#### Configuration

```yaml
telemetry:
  logs:
    level: info
    format: json
  traces:
    enabled: true
    endpoint: "http://otel-collector:4317"
  metrics:
    enabled: true
    endpoint: "http://otel-collector:4317"
```

## Usage

### Agent Configuration

Configure the agent to route through Warden and trust its CA.

**TCP (container sidecar):**

```bash
export HTTP_PROXY=http://warden:8080
export HTTPS_PROXY=http://warden:8080
export SSL_CERT_FILE=/shared/warden-ca.crt
```

**vsock (microVM):**

```bash
export HTTP_PROXY=http://vsock://2:8080       # CID 2 = host
export HTTPS_PROXY=http://vsock://2:8080
export SSL_CERT_FILE=/etc/warden/ca.crt
```

Note: most HTTP clients don't support vsock URIs natively. In microVM deployments, a lightweight vsock-to-TCP bridge runs inside the guest, exposing a local TCP port that forwards to Warden over vsock. The agent connects to the local bridge as a normal HTTP proxy.

```bash
# Inside guest VM: bridge listens on localhost, forwards to host vsock
warden-bridge --listen 127.0.0.1:8080 --vsock-cid 2 --vsock-port 8080

export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

### Running Warden

```bash
warden --config /etc/warden/config.yaml
```

### Configuration

```yaml
server:
  listen: "0.0.0.0:8080"                  # TCP
  # listen: "vsock://:8080"               # or vsock (CID assigned by hypervisor)
  health_listen: "0.0.0.0:9090"

ca:
  auto: true
  cert_output: /shared/warden-ca.crt     # or provide cert/key for external CA

dns:
  servers: ["8.8.8.8:53", "1.1.1.1:53"]
  cache:
    enabled: true
  deny_resolved_ips:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "127.0.0.0/8"

secrets:
  - type: env
  - type: file
    path: /run/secrets

policies:
  - name: block-github-admin
    host: "api.github.com"
    path: "/orgs/*/members"
    action: deny

  - name: github-api
    host: "api.github.com"
    path: "/repos/myorg/**"
    methods: ["GET", "POST", "PATCH"]
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${GITHUB_TOKEN}"

  - name: pypi-read-only
    host: "pypi.org"
    methods: ["GET"]
    action: allow

telemetry:
  logs:
    level: info
    format: json
  traces:
    enabled: true
    endpoint: "http://otel-collector:4317"
  metrics:
    enabled: true
    endpoint: "http://otel-collector:4317"
```

## Extensibility

Warden is built around Go interfaces so new backends can be added without modifying core proxy logic.

```go
// SecretSource resolves secret variable references.
type SecretSource interface {
	// Name returns the source type identifier (e.g., "env", "file", "vault").
	Name() string

	// Resolve looks up a secret by variable name.
	// Returns the value and true if found, or empty and false if not.
	Resolve(ctx context.Context, name string) (string, bool, error)
}

// TelemetryExporter exports proxy telemetry.
type TelemetryExporter interface {
	// LogRequest records a completed proxy request.
	LogRequest(ctx context.Context, entry RequestLog) error

	// Close flushes and shuts down the exporter.
	Close(ctx context.Context) error
}
```

To add a new secret backend (e.g., Vault), implement `SecretSource` and register it in the config parser. Same pattern for telemetry exporters.

The policy engine is also behind an interface, so it can be swapped for a more sophisticated engine (e.g., Cedar, OPA) without changing the proxy:

```go
// PolicyEngine evaluates whether a request is allowed and what to inject.
type PolicyEngine interface {
	// Evaluate checks a request against policies.
	// Returns the decision and any injection directives.
	Evaluate(ctx context.Context, req *RequestContext) (*PolicyDecision, error)
}
```

## Development

### Prerequisites

- Go 1.26+
- GNU Make

### Build

```bash
make build
```

### Test

```bash
make test          # all tests
make test-race     # with race detector
make fuzz          # all fuzz targets (30s each)
make coverage      # HTML coverage report
```

### Run locally

```bash
make run CONFIG=config.example.yaml
```

### All targets

```bash
make help
```

| Target | Description |
|--------|-------------|
| `make` | Full pipeline: deps → lint → test → build |
| `make build` | Build `warden` and `warden-bridge` binaries |
| `make test` | Run all tests |
| `make test-race` | Run tests with race detector |
| `make fuzz` | Run all fuzz targets (`FUZZ_TIME=30s`) |
| `make lint` | Run `go vet` + `staticcheck` |
| `make coverage` | Generate HTML coverage report |
| `make bench` | Run benchmarks |
| `make deps-update` | Update all dependencies to latest |
| `make clean` | Remove build artifacts |

### Project structure

```
cmd/
  warden/           # Main proxy server
  warden-bridge/    # vsock-to-TCP bridge (runs inside guest VM)
internal/
  proxy/            # MITM proxy, TLS interception, HTTP handling
  listener/         # TCP and vsock listener abstraction
  policy/           # Policy engine, matching, config parsing
  inject/           # Secret resolution, header/query injection
  secrets/          # SecretSource implementations (env, file, ...)
  telemetry/        # Logging, metrics, traces exporters
  dns/              # DNS resolver, caching, IP denylist
  health/           # Health check server
  config/           # YAML config parsing and validation
```

## License

Proprietary — Hummingbird AI
