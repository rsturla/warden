# Deployment

Warden runs as a sidecar — one instance per agent. Each agent gets its own Warden with its own policy configuration.

## Kubernetes / OpenShift (Separate Pods)

The recommended deployment model uses separate pods for the agent and Warden. NetworkPolicy enforces that the agent can only reach the internet through Warden — no bypass possible. This works with OpenShift's default `restricted-v2` SCC with no special privileges.

```
┌─────────────────────┐     ┌─────────────────────┐
│  Agent Pod          │     │  Warden Pod          │
│                     │     │                      │
│  HTTP_PROXY=warden  │────▶│  :8080 proxy         │────▶ upstream
│  SSL_CERT_FILE=...  │     │  :9090 health        │
│                     │     │                      │
│  NetworkPolicy:     │     │  NetworkPolicy:      │
│   egress → warden   │     │   egress → anywhere  │
│   only              │     │   ingress ← agent    │
└─────────────────────┘     └─────────────────────┘
```

### Namespace setup

All resources live in a shared namespace. The agent and Warden are labeled separately so NetworkPolicy can target them independently.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: agent-sandbox
```

### Warden Deployment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: warden-config
  namespace: agent-sandbox
data:
  config.yaml: |
    server:
      listen: "0.0.0.0:8080"
      health_listen: "0.0.0.0:9090"
    ca:
      auto: true
      cert_output: /shared/warden-ca.crt
    dns:
      cache:
        enabled: true
      deny_resolved_ips:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "169.254.0.0/16"
    secrets:
      - type: env
    policies:
      - name: block-metadata
        host: "169.254.169.254"
        action: deny
      - name: allow-github
        host: "api.github.com"
        path: "/repos/myorg/**"
        methods: ["GET", "POST"]
        action: allow
        inject:
          headers:
            Authorization: "Bearer ${GITHUB_TOKEN}"
---
apiVersion: v1
kind: Secret
metadata:
  name: warden-secrets
  namespace: agent-sandbox
type: Opaque
stringData:
  GITHUB_TOKEN: "ghp_your_token_here"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: warden
  namespace: agent-sandbox
spec:
  replicas: 1
  selector:
    matchLabels:
      app: warden
  template:
    metadata:
      labels:
        app: warden
    spec:
      volumes:
        - name: config
          configMap:
            name: warden-config
        - name: shared-ca
          emptyDir: {}
      containers:
        - name: warden
          image: warden:latest
          args: ["-config", "/etc/warden/config.yaml"]
          envFrom:
            - secretRef:
                name: warden-secrets
          ports:
            - containerPort: 8080
              name: proxy
            - containerPort: 9090
              name: health
          volumeMounts:
            - name: config
              mountPath: /etc/warden
            - name: shared-ca
              mountPath: /shared
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9090
          readinessProbe:
            httpGet:
              path: /readyz
              port: 9090
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 128Mi
---
apiVersion: v1
kind: Service
metadata:
  name: warden
  namespace: agent-sandbox
spec:
  selector:
    app: warden
  ports:
    - name: proxy
      port: 8080
      targetPort: proxy
    - name: health
      port: 9090
      targetPort: health
```

### Agent Deployment

The agent gets proxy env vars pointing to Warden's Service. The CA certificate is served by Warden and must be made available to the agent — either by copying from Warden's shared volume, baking into the agent image, or mounting from a shared PVC.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent
  namespace: agent-sandbox
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agent
  template:
    metadata:
      labels:
        app: agent
    spec:
      containers:
        - name: agent
          image: my-agent:latest
          env:
            - name: HTTP_PROXY
              value: "http://warden.agent-sandbox.svc:8080"
            - name: HTTPS_PROXY
              value: "http://warden.agent-sandbox.svc:8080"
            - name: SSL_CERT_FILE
              value: "/etc/warden-ca/warden-ca.crt"
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
```

### NetworkPolicy

These policies enforce that the agent can only talk to Warden, and Warden can reach external services. The agent has no direct internet access.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress
  namespace: agent-sandbox
spec:
  podSelector:
    matchLabels:
      app: agent
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: warden
      ports:
        - port: 8080
          protocol: TCP
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: warden-ingress
  namespace: agent-sandbox
spec:
  podSelector:
    matchLabels:
      app: warden
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: agent
      ports:
        - port: 8080
          protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: warden-egress
  namespace: agent-sandbox
spec:
  podSelector:
    matchLabels:
      app: warden
  policyTypes:
    - Egress
  egress:
    - {}
```

### CA certificate distribution

Warden auto-generates a CA certificate on startup and writes it to `cert_output`. To distribute it to agent pods, use one of:

1. **Init container** — an init container on the agent pod curls the CA cert from a Warden endpoint or copies from a shared volume
2. **ConfigMap** — if using an external CA (`ca.cert` + `ca.key` in config), store the public cert in a ConfigMap and mount it into both pods
3. **Baked into agent image** — for static environments, add the CA cert at image build time

Option 2 (external CA via ConfigMap) is recommended for production — the CA is stable across restarts and can be distributed before Warden starts.

## Multi-Tenant Kubernetes (Shared Warden)

A single Warden pod serves multiple agent pods. Each agent is identified by mTLS client certificate. Policies and secrets are isolated per tenant.

```
┌──────────────────────────┐
│ Agent Pod A              │
│ ┌────────┐ ┌───────────┐ │     ┌─────────────────┐
│ │ Agent  │→│  Bridge   │─┼─mTLS→│                 │
│ │        │ │ (sidecar) │ │     │  Warden Pod     │
│ │HTTP_   │ │ cert:     │ │     │  (Deployment)   │
│ │PROXY=  │ │ alpha.crt │ │     │                 │
│ │local   │ └───────────┘ │     │  tenants.d/     │
│ └────────┘               │     │  ├─ alpha.yaml  │
└──────────────────────────┘     │  └─ beta.yaml   │
                                 │                 │
┌──────────────────────────┐     │  server.tls:    │
│ Agent Pod B              │     │   client_ca     │──▶ upstream
│ ┌────────┐ ┌───────────┐ │     │                 │
│ │ Agent  │→│  Bridge   │─┼─mTLS→│                 │
│ │        │ │ cert:     │ │     └─────────────────┘
│ └────────┘ │ beta.crt  │ │          Service:
│            └───────────┘ │       warden:8443
└──────────────────────────┘
```

### Warden Deployment (multi-tenant)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: warden-config
  namespace: agent-sandbox
data:
  config.yaml: |
    server:
      listen: "0.0.0.0:8443"
      health_listen: "0.0.0.0:9090"
      tls:
        cert: /etc/warden/tls/tls.crt
        key: /etc/warden/tls/tls.key
        client_ca: /etc/warden/tls/tenant-ca.crt
    ca:
      cert: /etc/warden/mitm/ca.crt
      key: /etc/warden/mitm/ca.key
    dns:
      cache:
        enabled: true
      deny_resolved_ips:
        - "169.254.169.254/32"
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
    tenants:
      dir: /etc/warden/tenants.d/
    telemetry:
      logs:
        level: info
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: warden-tenants
  namespace: agent-sandbox
data:
  agent-alpha.yaml: |
    policies:
      - name: allow-github
        host: "api.github.com"
        path: "/repos/acme/**"
        methods: ["GET", "POST"]
        action: allow
        inject:
          headers:
            Authorization: "Bearer ${ALPHA_GITHUB_TOKEN}"
    secrets:
      - type: env
  agent-beta.yaml: |
    policies:
      - name: allow-pypi
        host: "pypi.org"
        methods: ["GET"]
        action: allow
    secrets:
      - type: env
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: warden
  namespace: agent-sandbox
spec:
  replicas: 1
  selector:
    matchLabels:
      app: warden
  template:
    metadata:
      labels:
        app: warden
    spec:
      volumes:
        - name: config
          configMap:
            name: warden-config
        - name: tenants
          configMap:
            name: warden-tenants
        - name: server-tls
          secret:
            secretName: warden-server-tls
        - name: mitm-ca
          secret:
            secretName: warden-mitm-ca
      containers:
        - name: warden
          image: warden:latest
          args: ["-config", "/etc/warden/config.yaml"]
          envFrom:
            - secretRef:
                name: warden-agent-secrets
          ports:
            - containerPort: 8443
              name: proxy
            - containerPort: 9090
              name: health
          volumeMounts:
            - name: config
              mountPath: /etc/warden
            - name: tenants
              mountPath: /etc/warden/tenants.d
            - name: server-tls
              mountPath: /etc/warden/tls
            - name: mitm-ca
              mountPath: /etc/warden/mitm
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9090
          readinessProbe:
            httpGet:
              path: /readyz
              port: 9090
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 128Mi
---
apiVersion: v1
kind: Service
metadata:
  name: warden
  namespace: agent-sandbox
spec:
  selector:
    app: warden
  ports:
    - name: proxy
      port: 8443
      targetPort: proxy
    - name: health
      port: 9090
      targetPort: health
```

### Agent with bridge sidecar

Each agent pod runs a `warden-bridge` sidecar that handles mTLS to Warden. The agent uses the bridge as a plain HTTP proxy on localhost.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-alpha
  namespace: agent-sandbox
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agent-alpha
  template:
    metadata:
      labels:
        app: agent-alpha
        role: agent
    spec:
      volumes:
        - name: client-cert
          secret:
            secretName: agent-alpha-cert
        - name: mitm-ca
          configMap:
            name: warden-mitm-ca-pub
      containers:
        - name: agent
          image: my-agent:latest
          env:
            - name: HTTP_PROXY
              value: "http://127.0.0.1:8080"
            - name: HTTPS_PROXY
              value: "http://127.0.0.1:8080"
            - name: SSL_CERT_FILE
              value: "/etc/warden-ca/ca.crt"
          volumeMounts:
            - name: mitm-ca
              mountPath: /etc/warden-ca

        - name: bridge
          image: warden:latest
          command: ["warden-bridge"]
          args:
            - "--listen=127.0.0.1:8080"
            - "--proxy-addr=warden.agent-sandbox.svc:8443"
            - "--client-cert=/etc/certs/tls.crt"
            - "--client-key=/etc/certs/tls.key"
            - "--proxy-ca=/etc/certs/ca.crt"
          volumeMounts:
            - name: client-cert
              mountPath: /etc/certs
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 100m
              memory: 32Mi
```

### Client certificate provisioning

Use [cert-manager](https://cert-manager.io/) to automate client certificate creation:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: tenant-ca-issuer
  namespace: agent-sandbox
spec:
  ca:
    secretName: tenant-ca-keypair
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: agent-alpha-cert
  namespace: agent-sandbox
spec:
  secretName: agent-alpha-cert
  commonName: agent-alpha
  usages:
    - client auth
  issuerRef:
    name: tenant-ca-issuer
```

Each `Certificate` resource creates a Kubernetes Secret containing `tls.crt`, `tls.key`, and `ca.crt`. The bridge sidecar mounts this Secret directly.

### NetworkPolicy (multi-tenant)

All agents share the same egress rule — they can only reach the Warden Service.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress
  namespace: agent-sandbox
spec:
  podSelector:
    matchLabels:
      role: agent
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: warden
      ports:
        - port: 8443
          protocol: TCP
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: warden-ingress
  namespace: agent-sandbox
spec:
  podSelector:
    matchLabels:
      app: warden
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: agent
      ports:
        - port: 8443
          protocol: TCP
```

### Adding a new agent

1. Create a `Certificate` resource (cert-manager generates the Secret)
2. Add tenant config to the `warden-tenants` ConfigMap
3. Deploy agent pod with bridge sidecar referencing the cert Secret

ConfigMap updates propagate to mounted volumes automatically (~60s kubelet sync). Warden's hot reload detects the new tenant file within ~30s. No restarts needed.

### Per-tenant secrets from Vault

For production, use [external-secrets-operator](https://external-secrets.io/) to sync per-tenant secrets from Vault into a single Kubernetes Secret that Warden reads via `env`:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: warden-agent-secrets
  namespace: agent-sandbox
spec:
  secretStoreRef:
    name: vault-backend
  target:
    name: warden-agent-secrets
  data:
    - secretKey: ALPHA_GITHUB_TOKEN
      remoteRef:
        key: agents/alpha/github
        property: token
    - secretKey: BETA_GITHUB_TOKEN
      remoteRef:
        key: agents/beta/github
        property: token
```

Tenant configs reference these as `${ALPHA_GITHUB_TOKEN}`, `${BETA_GITHUB_TOKEN}`, etc. Each tenant's policy only references its own variables — the `env` source is shared but tenants cannot see each other's variable names because injection only happens for variables referenced in that tenant's policies.

## Same-Pod Sidecar (Alternative)

For simpler deployments where NetworkPolicy enforcement is not required, the agent and Warden can run in the same pod. They communicate over `localhost` TCP. Note that without NetworkPolicy isolation, the agent could bypass Warden and connect directly to external services.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent-with-warden
spec:
  volumes:
    - name: shared-ca
      emptyDir: {}
    - name: warden-config
      configMap:
        name: warden-config
  containers:
    - name: agent
      image: my-agent:latest
      env:
        - name: HTTP_PROXY
          value: "http://localhost:8080"
        - name: HTTPS_PROXY
          value: "http://localhost:8080"
        - name: SSL_CERT_FILE
          value: "/shared/warden-ca.crt"
      volumeMounts:
        - name: shared-ca
          mountPath: /shared

    - name: warden
      image: warden:latest
      args: ["-config", "/etc/warden/config.yaml"]
      ports:
        - containerPort: 9090
          name: health
      volumeMounts:
        - name: shared-ca
          mountPath: /shared
        - name: warden-config
          mountPath: /etc/warden
      livenessProbe:
        httpGet:
          path: /healthz
          port: 9090
      readinessProbe:
        httpGet:
          path: /readyz
          port: 9090
```

## MicroVM (Firecracker, Cloud Hypervisor, QEMU)

Warden runs on the host. The agent runs inside a guest VM with no network interface. Communication uses vsock — a direct host-guest channel that doesn't require networking.

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

### vsock bridge

Most HTTP clients don't support vsock URIs. The `warden-bridge` binary runs inside the guest VM, exposing a local TCP port that forwards traffic to Warden over vsock.

```bash
# Inside guest VM
warden-bridge --listen 127.0.0.1:8080 --vsock-cid 2 --vsock-port 8080

# Agent uses the bridge as a normal HTTP proxy
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

### Warden config for vsock

```yaml
server:
  listen: "vsock://:8080"
```

## Agent Trust Setup

The agent must trust Warden's CA certificate for HTTPS interception to work.

### System trust store

```bash
# RHEL/CentOS/Fedora
cp /shared/warden-ca.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust

# Debian/Ubuntu
cp /shared/warden-ca.crt /usr/local/share/ca-certificates/warden-ca.crt
update-ca-certificates
```

### Per-process

```bash
export SSL_CERT_FILE=/shared/warden-ca.crt
```

### Language-specific

Some runtimes/libraries have their own trust stores:

```bash
# Node.js
export NODE_EXTRA_CA_CERTS=/shared/warden-ca.crt

# Python requests
export REQUESTS_CA_BUNDLE=/shared/warden-ca.crt
```

## Multi-Tenant Deployment (mTLS)

A single Warden instance can serve multiple agents, each identified by mTLS client certificate. Each agent gets isolated policies and secrets. See [Configuration](configuration.md) for config format.

### Certificate setup

Three certificate concerns, all independent:

| Certificate | Purpose | Per-tenant? |
|-------------|---------|-------------|
| Server cert (`server.tls.cert`) | Warden's identity to agents | No, one for Warden |
| Client cert (on each agent) | Agent identity to Warden | Yes, one per agent |
| MITM CA (`ca.cert`) | HTTPS interception | No, shared |

Generate a tenant CA and per-agent client certificates:

```bash
# Tenant CA (signs all agent client certs)
openssl ecparam -genkey -name prime256v1 -out tenant-ca.key
openssl req -new -x509 -key tenant-ca.key -out tenant-ca.crt -days 365 \
  -subj "/CN=Warden Tenant CA"

# Per-agent client cert (CN = tenant ID = config filename)
openssl ecparam -genkey -name prime256v1 -out agent-alpha.key
openssl req -new -key agent-alpha.key -out agent-alpha.csr \
  -subj "/CN=agent-alpha"
openssl x509 -req -in agent-alpha.csr -CA tenant-ca.crt -CAkey tenant-ca.key \
  -CAcreateserial -out agent-alpha.crt -days 365
```

### Agent connection via warden-bridge

Most HTTP clients don't support proxy client certificates natively. Use `warden-bridge` in TLS mode as a local forwarder:

```bash
# On agent machine — bridge handles mTLS to Warden
warden-bridge \
  --listen 127.0.0.1:8080 \
  --proxy-addr warden.internal:8443 \
  --client-cert /etc/certs/agent-alpha.crt \
  --client-key /etc/certs/agent-alpha.key \
  --proxy-ca /etc/certs/tenant-ca.crt

# Agent uses bridge as plain HTTP proxy
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

```
Agent process ──HTTP──▶ localhost:8080 (bridge) ──mTLS──▶ Warden :8443
                        adds client cert                  extracts CN
                        automatically                     applies tenant config
```

### warden-bridge flags

| Flag | Description |
|------|-------------|
| `--listen` | Local TCP listen address (default: `127.0.0.1:8080`) |
| `--vsock-cid` | vsock context ID (vsock mode) |
| `--vsock-port` | vsock port (vsock mode) |
| `--proxy-addr` | Warden proxy TCP address (TLS mode) |
| `--client-cert` | Client certificate PEM for mTLS (TLS mode, required) |
| `--client-key` | Client key PEM for mTLS (TLS mode, required) |
| `--proxy-ca` | CA to verify Warden's server cert (TLS mode, optional) |

Modes are mutually exclusive: use either `--vsock-cid`/`--vsock-port` or `--proxy-addr`.

## Health Checks

Warden exposes health endpoints on a separate port so agents cannot access them through the proxy.

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness — Warden process is running |
| `GET /readyz` | Readiness — config loaded, CA initialized |
| `GET /tenantz` | Tenant list — loaded tenant IDs and count (multi-tenant mode only, 404 in single-tenant) |

```yaml
server:
  health_listen: "0.0.0.0:9090"
```

## Build

```bash
make build           # Dev build
make release         # Production: stripped, static, CGO_ENABLED=0
```

The release build produces a statically-linked binary suitable for scratch/distroless containers.
