# Configuration Reference

Warden is configured via a single YAML file, passed with `--config`.

```bash
warden --config /etc/warden/config.yaml
```

## Full Configuration

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
