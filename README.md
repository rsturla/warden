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

Warden runs as a sidecar — one instance per agent. Each agent gets its own Warden with its own policy configuration. The agent connects to Warden over TCP or vsock depending on the deployment model. See [Deployment](docs/deployment.md) for full setup guides.

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
│  HTTP_PROXY=bridge  │
└─────────────────────┘
```

### HTTPS Request Flow

1. Agent sends `CONNECT` to Warden; Warden presents a dynamically generated certificate for the target host, signed by its CA
2. Warden decrypts the request and evaluates it against policy rules (host, path, method)
3. If no rule matches → `403 Forbidden` (default deny). If deny rule matches → `403 Forbidden`.
4. If allowed → Warden injects secrets (if configured), opens a real TLS connection upstream, and relays the response

### Supported Protocols

| Protocol | Support | Notes |
|----------|---------|-------|
| HTTP/1.1 | yes | Direct inspection, policy + injection |
| HTTPS | yes | MITM — TLS termination, inspection, re-encryption |
| HTTP/2 | yes | Transparent via Go stdlib. Works with gRPC (`/package.Service/Method`) |
| WebSocket | upgrade only | Policy evaluated on upgrade request. Frames pass through post-upgrade |

## Quick Start

```bash
# Build
make build

# Run with example config
make run CONFIG=config.example.yaml

# Configure agent to use Warden
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export SSL_CERT_FILE=/tmp/warden-ca.crt
```

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration](docs/configuration.md) | Full config reference, defaults, validation rules |
| [Policies](docs/policies.md) | Policy rules, glob patterns, evaluation order, injection |
| [Secrets](docs/secrets.md) | All secret backends: env, file, vault, kubernetes, github-app |
| [Telemetry](docs/telemetry.md) | Logs, traces, metrics, OTLP setup |
| [DNS](docs/dns.md) | DNS resolution, DNS-over-TLS, caching, IP denylist |
| [Deployment](docs/deployment.md) | Container sidecar, microVM, agent trust setup, health checks |
| [Development](docs/development.md) | Building, testing, fuzzing, project structure, extending |

## Example Configuration

```yaml
server:
  listen: "0.0.0.0:8080"
  health_listen: "0.0.0.0:9090"

ca:
  auto: true
  cert_output: /shared/warden-ca.crt

dns:
  servers: ["8.8.8.8:53"]
  cache:
    enabled: true
  deny_resolved_ips:
    - "10.0.0.0/8"
    - "169.254.0.0/16"
    - "127.0.0.0/8"

secrets:
  - type: env
  - type: file
    path: /run/secrets

policies:
  - name: block-metadata
    host: "169.254.169.254"
    action: deny

  - name: github-api
    host: "api.github.com"
    path: "/repos/myorg/**"
    methods: ["GET", "POST"]
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${GITHUB_TOKEN}"

  - name: pypi-read-only
    host: "pypi.org"
    methods: ["GET"]
    action: allow
```

See [Configuration](docs/configuration.md) for the full reference.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
