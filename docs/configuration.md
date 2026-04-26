# Configuration Reference

Warden is configured via a YAML file, passed with `--config`. Warden supports two modes: **single-tenant** (one config file with policies and secrets) and **multi-tenant** (global config + per-tenant config files with mTLS identification).

```bash
warden --config /etc/warden/config.yaml
```

## Full Configuration (Single-Tenant)

```yaml
server:
  listen: "0.0.0.0:8080"                  # TCP listener address
  # listen: "vsock://:8080"               # vsock listener (microVM deployments)
  health_listen: "0.0.0.0:9090"           # Health check listener (separate from proxy)

ca:
  auto: true                               # Generate self-signed CA on startup
  cert_output: /shared/warden-ca.crt       # Write CA cert here for agent trust setup
  # cert: /etc/warden/ca.crt              # External CA cert (mutually exclusive with auto)
  # key: /etc/warden/ca.key               # External CA key

dns:
  servers: ["8.8.8.8:53", "1.1.1.1:53"]   # Upstream DNS servers (UDP)
  dot:
    enabled: false                          # DNS-over-TLS
    server: "1.1.1.1:853"                  # DoT server (required when enabled)
  cache:
    enabled: true
    max_ttl: 300                            # Cache TTL in seconds (default: 300)
  deny_resolved_ips:                        # Block connections to resolved IPs in these CIDRs
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "127.0.0.0/8"

secrets:                                    # Secret sources, checked in order
  - type: env
  - type: file
    path: /run/secrets
  # See docs/secrets.md for vault, kubernetes, github-app

policies:                                   # See docs/policies.md
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

telemetry:                                  # See docs/telemetry.md
  logs:
    level: info                             # info, warn, error
    format: json                            # json only
  traces:
    enabled: false
    endpoint: "http://otel-collector:4317"
  metrics:
    enabled: false
    endpoint: "http://otel-collector:4317"
```

## Defaults

| Field | Default |
|-------|---------|
| `server.listen` | `0.0.0.0:8080` |
| `server.health_listen` | `0.0.0.0:9090` |
| `telemetry.logs.level` | `info` |
| `telemetry.logs.format` | `json` |
| `dns.cache.max_ttl` | `300` |
| `policies[].path` | `/**` (match all paths) |

## Validation Rules

- Policy names must be unique and non-empty
- Every policy requires `host` and `action`
- `action` must be `allow` or `deny` (case-insensitive)
- `deny` rules cannot have `inject` blocks
- HTTP methods must be uppercase (`GET`, not `get`)
- Secret source types must be one of: `env`, `file`, `vault`, `kubernetes`, `github-app`
- If `dns.dot.enabled` is true, `dns.dot.server` is required
- If `telemetry.traces.enabled` is true, `telemetry.traces.endpoint` is required
- If `telemetry.metrics.enabled` is true, `telemetry.metrics.endpoint` is required
- `deny_resolved_ips` entries must be valid CIDR notation (IPv4 or IPv6)

## Environment Variables

Warden itself reads no environment variables for configuration. All configuration is via the YAML file. However, the `env` secret source resolves `${VAR}` references from the process environment, and the `vault` backend reads `VAULT_TOKEN` for token-based auth.

## CA Modes

### Auto-generated (default)

Best for dev and ephemeral sidecars. Warden generates a self-signed ECDSA P-256 CA on startup. If `cert_output` is set, the CA certificate is written there for agents to trust.

```yaml
ca:
  auto: true
  cert_output: /shared/warden-ca.crt
```

### External CA

Bring your own CA. Use when the organization controls the root of trust or needs centralized key rotation.

```yaml
ca:
  cert: /etc/warden/ca/warden-ca.crt
  key: /etc/warden/ca/warden-ca.key
```

If both `cert`/`key` and `auto` are set, the external CA takes precedence.

## Multi-Tenant Mode

Multi-tenant mode allows a single Warden instance to serve multiple agents, each with isolated policies and secrets. Tenants are identified by mTLS client certificate CN (Common Name).

### Directory layout

```
/etc/warden/
├── config.yaml              # Global config (server, CA, DNS, telemetry)
└── tenants.d/               # Per-tenant configs
    ├── agent-alpha.yaml     # CN=agent-alpha
    ├── agent-beta.yaml      # CN=agent-beta
    └── ci-runner.yaml       # CN=ci-runner
```

### Global config (multi-tenant)

When `tenants` is set, root-level `policies` and `secrets` must be omitted — they live in per-tenant files.

```yaml
server:
  listen: "0.0.0.0:8443"
  health_listen: "0.0.0.0:9090"
  tls:
    cert: /etc/warden/server.crt           # Warden's server certificate
    key: /etc/warden/server.key            # Warden's server key
    client_ca: /etc/warden/tenant-ca.crt   # CA that signed agent client certs

ca:
  cert: /etc/warden/mitm-ca.crt
  key: /etc/warden/mitm-ca.key

dns:
  cache:
    enabled: true
  deny_resolved_ips:
    - "169.254.169.254/32"
    - "10.0.0.0/8"

tenants:
  dir: /etc/warden/tenants.d/

telemetry:
  logs:
    level: info
```

### Per-tenant config

Each file in the tenant directory defines policies and secrets for one tenant. The filename (without extension) is the tenant ID, which must match the client certificate CN.

```yaml
# tenants.d/agent-alpha.yaml
policies:
  - name: allow-github
    host: "api.github.com"
    path: "/repos/acme/**"
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${GITHUB_TOKEN}"

secrets:
  - type: vault
    address: https://vault.internal:8200
    prefix: agents/alpha/
    auth: kubernetes
```

### Server TLS

| Field | Required | Description |
|-------|----------|-------------|
| `server.tls.cert` | yes | PEM-encoded server certificate |
| `server.tls.key` | yes | PEM-encoded server private key |
| `server.tls.client_ca` | yes | CA certificate for verifying client certs |

**Note:** `server.tls` configures TLS on the proxy listener (agent→Warden). This is separate from the `ca` section, which configures the MITM CA for HTTPS interception (Warden→upstream).

### Tenants

| Field | Required | Description |
|-------|----------|-------------|
| `tenants.dir` | yes | Directory containing per-tenant YAML files |

### Hot reload

Warden polls the tenant directory every 30 seconds. Changes take effect without restart:
- New file → tenant available
- Deleted file → tenant rejected (403)
- Modified file → new policies/secrets applied

In-flight requests complete with the old configuration. Failed reloads (invalid YAML, bad policy) are logged and the previous config is preserved.

### Validation rules (multi-tenant)

- `tenants` requires `server.tls` (mTLS is mandatory for tenant identification)
- `server.tls` requires all three fields: `cert`, `key`, `client_ca`
- Root-level `policies` must be empty when `tenants` is set
- Root-level `secrets` must be empty when `tenants` is set
- Per-tenant files follow the same policy/secret validation as single-tenant mode
