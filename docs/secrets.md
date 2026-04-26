# Secret Sources

Secret sources define where `${VAR}` references in [policy injection](policies.md) are resolved from. Sources are checked in the order they appear in the config. First match wins.

```yaml
secrets:
  - type: env
  - type: file
    path: /run/secrets
  - type: vault
    address: https://vault.example.com:8200
```

If a referenced variable is not found in any source, the request is **denied** (fail-closed).

## Environment Variables (`env`)

Resolves variables from Warden's process environment.

```yaml
secrets:
  - type: env
```

Variable `${GITHUB_TOKEN}` resolves to the value of the `GITHUB_TOKEN` environment variable.

## File (`file`)

Reads secrets from files in a directory. Each file's name is the variable name, its content (trimmed) is the value. Uses `os.Root` for path traversal protection.

```yaml
secrets:
  - type: file
    path: /run/secrets
```

Variable `${GITHUB_TOKEN}` reads `/run/secrets/GITHUB_TOKEN`.

| Field | Required | Description |
|-------|----------|-------------|
| `path` | yes | Directory containing secret files |

## HashiCorp Vault (`vault`)

Resolves secrets from Vault's KV v2 secrets engine via HTTP API. Zero external dependencies — uses stdlib `net/http`.

```yaml
secrets:
  - type: vault
    address: https://vault.example.com:8200
    mount: secret                              # KV mount path (default: "secret")
    prefix: warden/                            # Prepended to all lookups (optional)
    auth: token                                # "token" or "kubernetes" (default: "token")
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `address` | yes | — | Vault server URL |
| `mount` | no | `secret` | KV v2 mount path |
| `prefix` | no | — | Prepended to variable name for Vault path |
| `auth` | no | `token` | Authentication method |

### Variable name format

Variables are resolved as `path/to/secret/key`:

- `${myapp/db/password}` → reads key `password` from Vault secret at `{mount}/data/{prefix}myapp/db`
- `${simple}` → reads key `simple` from Vault secret at `{mount}/data/{prefix}simple`

### Authentication

**Token auth** (default): reads `VAULT_TOKEN` from the environment.

```yaml
auth: token
```

**Kubernetes auth**: uses the pod's service account JWT to authenticate with Vault. Reads the token from `/var/run/secrets/kubernetes.io/serviceaccount/token`. The Vault role defaults to `warden` and can be overridden with the `VAULT_K8S_ROLE` environment variable.

```yaml
auth: kubernetes
```

Tokens are cached and automatically refreshed before expiry.

## Kubernetes Secrets (`kubernetes`)

Reads secrets from the Kubernetes API. Designed for in-cluster use — authenticates with the pod's service account. Zero external dependencies.

```yaml
secrets:
  - type: kubernetes
    namespace: my-namespace                    # Optional. Defaults to pod's namespace
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `namespace` | no | Pod's namespace | Kubernetes namespace to read secrets from |

### Variable name format

Variables are resolved as `secretname/key`:

- `${db-creds/password}` → reads key `password` from Kubernetes secret `db-creds`
- `${api-key}` → reads key `api-key` from Kubernetes secret `api-key`

Values are automatically base64-decoded (Kubernetes API returns base64-encoded secret data).

### Prerequisites

- Warden must run inside a Kubernetes pod
- The service account needs RBAC permission to `get` secrets in the target namespace
- Service account token and CA cert are read from standard paths under `/var/run/secrets/kubernetes.io/serviceaccount/`

### Example RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: warden-secrets-reader
  namespace: my-namespace
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: warden-secrets-reader
  namespace: my-namespace
subjects:
  - kind: ServiceAccount
    name: warden
roleRef:
  kind: Role
  name: warden-secrets-reader
  apiGroup: rbac.authorization.k8s.io
```

## GitHub App (`github-app`)

Generates GitHub App installation access tokens dynamically. Handles the full lifecycle: RSA JWT signing, installation token exchange, caching, and automatic refresh. Zero external dependencies — JWT is constructed with stdlib `crypto/rsa` and `crypto/sha256`.

```yaml
secrets:
  - type: github-app
    app_id: 12345
    installation_id: 67890
    private_key_path: /etc/warden/github-app.pem
```

| Field | Required | Description |
|-------|----------|-------------|
| `app_id` | yes | GitHub App ID (positive integer) |
| `installation_id` | yes | GitHub App installation ID (positive integer) |
| `private_key_path` | yes | Path to PEM-encoded RSA private key (PKCS#1 or PKCS#8) |

### Variable name

This source responds only to the variable name `GITHUB_TOKEN`. All other names return not-found.

```yaml
inject:
  headers:
    Authorization: "Bearer ${GITHUB_TOKEN}"
```

### Token lifecycle

1. Warden signs a short-lived JWT (RS256, 10-minute expiry) using the app's private key
2. Exchanges the JWT for an installation access token via `POST /app/installations/{id}/access_tokens`
3. Caches the installation token (valid for 1 hour)
4. Automatically refreshes when the token has less than 5 minutes remaining
5. Thread-safe — concurrent requests share the cached token

### GitHub Enterprise

For GitHub Enterprise Server, set the `GITHUB_API_BASE` environment variable:

```bash
export GITHUB_API_BASE=https://github.example.com/api/v3
```

## GCP Service Account (`gcp-service-account`)

Generates Google Cloud OAuth2 access tokens from a service account. Supports two authentication modes: credentials file (service account key JSON) and GCE metadata server (for workloads running on Google Cloud infrastructure). Zero external dependencies.

```yaml
secrets:
  - type: gcp-service-account
    credentials_file: /etc/warden/sa-key.json
    scopes:
      - https://www.googleapis.com/auth/cloud-platform
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `credentials_file` | no | — | Path to service account key JSON. If omitted, uses GCE metadata server |
| `scopes` | no | `cloud-platform` | OAuth2 scopes (used with credentials file only) |
| `token_name` | no | `GCP_ACCESS_TOKEN` | Variable name this source responds to |

### Variable name

By default, this source responds to `GCP_ACCESS_TOKEN`. Use `token_name` to configure a custom name — useful when multiple service accounts serve different APIs:

```yaml
secrets:
  - type: gcp-service-account
    credentials_file: /etc/warden/vertex-sa.json
    token_name: GCP_VERTEX_TOKEN
    scopes:
      - https://www.googleapis.com/auth/cloud-platform

  - type: gcp-service-account
    credentials_file: /etc/warden/docs-sa.json
    token_name: GCP_DOCS_TOKEN
    scopes:
      - https://www.googleapis.com/auth/documents
```

Each source instance responds only to its own `token_name`. All other names return not-found.

```yaml
inject:
  headers:
    Authorization: "Bearer ${GCP_ACCESS_TOKEN}"
```

### Authentication

**Credentials file** (default when `credentials_file` is set): reads the service account key JSON, signs a JWT (RS256) with the embedded private key, and exchanges it at Google's token endpoint for an access token.

```yaml
secrets:
  - type: gcp-service-account
    credentials_file: /etc/warden/sa-key.json
```

**GCE metadata server** (default when `credentials_file` is omitted): fetches access tokens from the instance metadata server. Use this when running on GCE, GKE, or Cloud Run where workload identity is configured.

```yaml
secrets:
  - type: gcp-service-account
```

### Token lifecycle

1. For credentials file: Warden signs a JWT (RS256, 1-hour expiry) and exchanges it at the token endpoint
2. For metadata: Warden fetches a token from the GCE metadata server
3. Caches the access token until near expiry (5-minute safety margin)
4. Refreshes at request time when the cached token is expired or expiring
5. Thread-safe — concurrent requests share the cached token

## GCP Authorized User (`gcp-authorized-user`)

Generates Google Cloud OAuth2 access tokens from a user's Application Default Credentials (ADC). Uses the refresh token flow — exchanges a stored refresh token for a short-lived access token. Zero external dependencies.

```yaml
secrets:
  - type: gcp-authorized-user
    credentials_file: /etc/warden/adc.json
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `credentials_file` | yes | — | Path to ADC JSON file (must be type `authorized_user`) |
| `token_name` | no | `GCP_ACCESS_TOKEN` | Variable name this source responds to |

### Credentials file

The credentials file must be an `authorized_user` JSON file, typically generated by `gcloud auth application-default login`. It contains `client_id`, `client_secret`, and `refresh_token`.

```json
{
  "type": "authorized_user",
  "client_id": "...",
  "client_secret": "...",
  "refresh_token": "..."
}
```

### Variable name

Same behavior as `gcp-service-account` — responds only to its `token_name` (default `GCP_ACCESS_TOKEN`). Use custom names when running multiple GCP sources:

```yaml
secrets:
  - type: gcp-authorized-user
    credentials_file: /etc/warden/dev-adc.json
    token_name: GCP_DEV_TOKEN
```

### Token lifecycle

1. Warden exchanges the refresh token at Google's token endpoint for an access token
2. Caches the access token until near expiry (5-minute safety margin)
3. Refreshes at request time when the cached token is expired or expiring
4. Thread-safe — concurrent requests share the cached token

### When to use

Use `gcp-authorized-user` for development and local testing where a developer's ADC is available. For production workloads, prefer `gcp-service-account` with a credentials file or GCE metadata server.

## Multi-Tenant Isolation

In multi-tenant mode, each tenant has its own secret sources defined in its config file (`tenants.d/<tenant-id>.yaml`). Secret chains are fully isolated — tenant A cannot access tenant B's secrets.

**Note:** the `env` source reads process-wide environment variables, which are shared across all tenants. For strict isolation, use `vault` or `file` sources with tenant-specific paths (e.g., different Vault prefixes per tenant).

## Source Chain

Sources are checked in config order. The first source that resolves a variable wins. If a source returns an error (not "not found", but an actual error), resolution stops and the request is denied.

```yaml
secrets:
  - type: env             # Check environment first
  - type: file            # Then files
    path: /run/secrets
  - type: vault           # Then Vault
    address: https://vault:8200
```

## Adding Custom Sources

Implement the `SecretSource` interface:

```go
type SecretSource interface {
    Name() string
    Resolve(ctx context.Context, name string) (string, bool, error)
}
```

Then register in `init()` using `secrets.Register()` and `config.RegisterSecretValidator()`. The registry pattern auto-discovers new types — no changes needed in `config.go` or `main.go`. See [Development](development.md).
