# Policies

Policies are ordered rules evaluated top-to-bottom against each decrypted request. **First match wins.** No match means deny.

## Rule Structure

```yaml
policies:
  - name: rule-name          # Required. Unique identifier, used in logs and telemetry
    host: "api.github.com"   # Required. Exact hostname or glob (*.example.com)
    path: "/repos/**"        # Optional. Path glob. Default: /** (match all)
    methods: ["GET", "POST"] # Optional. HTTP methods. Default: all methods
    action: allow            # Required. "allow" or "deny"
    inject:                  # Optional. Only valid on allow rules
      headers:
        Authorization: "Bearer ${GITHUB_TOKEN}"
      query:
        api_key: "${API_KEY}"
```

## Match Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `name` | yes | — | Rule identifier (must be unique) |
| `host` | yes | — | Exact hostname or glob (`*.example.com`) |
| `path` | no | `/**` | Path glob (`*` = one segment, `**` = any depth) |
| `methods` | no | all | HTTP methods (must be uppercase) |
| `action` | yes | — | `allow` or `deny` |

## Glob Patterns

### Host globs

- `api.github.com` — exact match
- `*.example.com` — wildcard on one domain label (matches `api.example.com`, not `a.b.example.com`)
- Case-insensitive

### Path globs

- `/repos/myorg/app` — exact path
- `/repos/*/pulls` — `*` matches exactly one path segment
- `/repos/myorg/**` — `**` matches zero or more segments at any depth
- `/v2/**/manifest` — `**` can appear mid-path

## Evaluation Order

1. Rules are checked in the order they appear in the config file
2. The first rule whose `host`, `path`, and `methods` all match the request determines the outcome
3. If the matching rule is `deny` → `403 Forbidden`
4. If the matching rule is `allow` → request is forwarded (with optional injection)
5. If no rule matches → `403 Forbidden` (default deny)

### Recommended ordering

```yaml
policies:
  # 1. Deny rules first — block dangerous endpoints before any allow
  - name: block-cloud-metadata
    host: "169.254.169.254"
    action: deny

  - name: block-loopback
    host: "localhost"
    action: deny

  # 2. Narrow deny rules for specific paths on otherwise-allowed hosts
  - name: block-github-admin
    host: "api.github.com"
    path: "/orgs/*/members"
    action: deny

  # 3. Allow rules — most specific first
  - name: github-api-read
    host: "api.github.com"
    path: "/repos/myorg/**"
    methods: ["GET"]
    action: allow

  # 4. Everything else is implicitly denied
```

## Injection

Allow rules can include an `inject` block to modify the request before forwarding. The agent never sees injected values.

```yaml
inject:
  headers:                         # Set/replace request headers
    Authorization: "Bearer ${GITHUB_TOKEN}"
    X-Custom: "static-value"       # Static strings work too
  query:                           # Set/replace query parameters
    api_key: "${API_KEY}"
```

### Behavior

- Injection **replaces** matching keys. If the agent sends a header or query parameter with the same name, Warden overwrites it. This prevents agents from supplying their own credentials.
- Values use `${VAR}` syntax. Variables are resolved from [secret sources](secrets.md) at request time.
- If a referenced variable cannot be resolved, the request is **denied** (fail-closed). This prevents forwarding requests without required authentication.
- `deny` rules cannot have `inject` blocks (rejected at config validation).

## Credential Intercept

Allow rules can include an `intercept` block to short-circuit the request and return a synthetic OAuth2 token response instead of forwarding to upstream. This enables transparent credential vending — agents and their SDKs call token endpoints as normal, but Warden resolves the credential locally and returns it without ever contacting the upstream provider.

```yaml
policies:
  - name: gcp-token-intercept
    host: "oauth2.googleapis.com"
    path: "/token"
    methods: ["POST"]
    action: allow
    intercept:
      credential: GCP_ACCESS_TOKEN
```

| Field | Required | Description |
|-------|----------|-------------|
| `credential` | yes | Secret variable name to resolve (e.g., `GCP_ACCESS_TOKEN`) |

### Behavior

- Warden resolves the credential from the tenant's [secret sources](secrets.md)
- Returns an HTTP 200 with a standard OAuth2 token response:
  ```json
  {"access_token": "<resolved>", "token_type": "Bearer", "expires_in": 3600}
  ```
- **No upstream connection is made** — the request never leaves Warden
- If credential resolution fails, the request is denied (fail-closed)
- Logged with action `intercept` in telemetry

### Constraints

- `deny` rules cannot have `intercept`
- `inject` and `intercept` are mutually exclusive on the same rule
- `intercept` requires a non-empty `credential`

### Use case

Agent SDKs (Google Cloud, etc.) call token endpoints to obtain credentials before making API calls. Without intercept, the SDK would fail because the agent has no credentials. With intercept, the SDK receives a valid token from Warden, then makes API calls normally. Combine with `inject` on API endpoint rules for defense in depth:

```yaml
policies:
  # Intercept token requests — SDK gets a token from Warden
  - name: gcp-token
    host: "oauth2.googleapis.com"
    path: "/token"
    methods: ["POST"]
    action: allow
    intercept:
      credential: GCP_ACCESS_TOKEN

  # Also inject auth on API calls — belt and suspenders
  - name: gcp-api
    host: "*.googleapis.com"
    path: "/**"
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${GCP_ACCESS_TOKEN}"
```

## HTTPS Early Rejection

For HTTPS connections, Warden performs a fast check at the `CONNECT` stage — before the TLS handshake. If no allow rule could possibly match the requested host, Warden immediately returns `403` without spending resources on TLS. This is powered by `PolicyEngine.CanMatchHost()`.

## Multi-Tenant Isolation

In multi-tenant mode, each tenant has its own policy list defined in a separate config file (`tenants.d/<tenant-id>.yaml`). Policies are fully isolated — tenant A's rules cannot affect tenant B's requests. See [Configuration](configuration.md) for the per-tenant config format.

Policy evaluation works identically per-tenant: first match wins, default deny. The tenant is resolved from the mTLS client certificate before any policy evaluation occurs.

## Security Considerations

- **Default-deny**: no implicit allow. Every allowed endpoint must be explicitly listed.
- **Fail-closed**: if secret resolution fails for an injected variable, the request is denied — not forwarded without auth.
- **DNS rebinding protection**: even if a hostname matches an allow rule, the resolved IP is checked against `deny_resolved_ips`. See [DNS](dns.md).
- **Agent credential override**: injection replaces agent-supplied headers, preventing agents from using their own tokens to bypass intended auth.
