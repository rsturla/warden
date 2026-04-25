# Deployment

Warden runs as a sidecar — one instance per agent. Each agent gets its own Warden with its own policy configuration.

## Container Sidecar (Kubernetes)

The agent and Warden run as containers in the same pod. They communicate over `localhost` TCP.

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

### Agent configuration

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export SSL_CERT_FILE=/shared/warden-ca.crt
```

### Pod spec example

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
      args: ["--config", "/etc/warden/config.yaml"]
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
