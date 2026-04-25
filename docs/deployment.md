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

## Health Checks

Warden exposes health endpoints on a separate port so agents cannot access them through the proxy.

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness — Warden process is running |
| `GET /readyz` | Readiness — config loaded, CA initialized |

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
