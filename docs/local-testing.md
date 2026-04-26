# Local Testing with kind

Test Warden with [Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) in a local kind cluster. The setup creates a full environment: Warden proxy, Agent Sandbox CRDs, an in-cluster test server, NetworkPolicies with Calico enforcement, and secret injection.

## Prerequisites

- [kind](https://kind.sigs.k8s.io/) v0.20+
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Docker](https://docs.docker.com/get-docker/) or Podman (with `docker` alias)

## Quick Start

```bash
./hack/kind/setup.sh    # create cluster, build, deploy everything
./hack/kind/test.sh     # run e2e tests
./hack/kind/teardown.sh # delete cluster
```

## What setup.sh Does

1. Creates a single-node kind cluster (`warden-sandbox`) with default CNI disabled
2. Installs Calico CNI for NetworkPolicy enforcement
3. Builds Warden and test server container images, loads into cluster
4. Installs Agent Sandbox CRDs, controller, and extensions (v0.4.2)
5. Deploys Warden with config, secrets, service, and NetworkPolicies
6. Deploys an in-cluster test server (echo server for verifying proxy behavior)
7. Creates a `Sandbox` (curl image) and a `SandboxTemplate` + `SandboxClaim` (Python image)
8. Waits for all pods to be ready

All tests use the in-cluster test server — no external service dependencies.

## Architecture

```
kind cluster (warden-sandbox, single node, Calico CNI)
├── kube-system/               Calico for NetworkPolicy enforcement
├── agent-sandbox-system/      Agent Sandbox controller
└── agent-sandbox/
    ├── Warden Deployment      policy proxy + secret injection
    ├── Warden Service         :8080 proxy, :9090 health
    ├── Test Server            echo server (header/path/method verification)
    ├── Sandbox: test-agent    curl-based agent (direct Sandbox)
    ├── SandboxClaim: dev-agent  Python agent (from SandboxTemplate)
    └── NetworkPolicies        agent → warden only, enforced by Calico
```

## Policy Configuration

| Host | Path | Methods | Action | Injection |
|------|------|---------|--------|-----------|
| `169.254.169.254` | `*` | `*` | deny | — |
| `test-server.agent-sandbox.svc` | `/api/v1/**` | GET | allow | — |
| `test-server.agent-sandbox.svc` | `/get` | GET | allow | — |
| `test-server.agent-sandbox.svc` | `/headers` | GET | allow | `Authorization: Bearer ${TEST_SECRET}` |
| Everything else | — | — | deny | — |

## Test Suite

`test.sh` runs 16 tests across 6 categories:

### Policy enforcement (allow/deny)

| # | Test | Expected |
|---|------|----------|
| 1 | GET /get via proxy | 200 |
| 2 | GET unknown host | 403 (default-deny) |
| 3 | GET 169.254.169.254 | 403 (metadata blocked) |

### Secret injection

| # | Test | Expected |
|---|------|----------|
| 4 | GET /headers — check Authorization value | Token present |
| 5 | GET /get — no injection on non-injecting policy | No Authorization header |

### Method filtering

| # | Test | Expected |
|---|------|----------|
| 6 | POST /post | 403 (only GET allowed) |
| 7 | POST /get | 403 (POST not in policy) |
| 8 | GET /get | 200 (GET works) |

### Path-based matching

| # | Test | Expected |
|---|------|----------|
| 9 | GET /api/v1/resource | 200 (path matches) |
| 10 | GET /api/v2/resource | 403 (path not in policy) |
| 11 | GET /nonexistent | 403 (path not in policy) |

### HTTPS CONNECT

| # | Test | Expected |
|---|------|----------|
| 12 | CONNECT to denied host | 403 (early rejection before TLS handshake) |

### Infrastructure

| # | Test | Expected |
|---|------|----------|
| 13 | Warden pod readiness/liveness probes | Ready, 0 restarts |
| 14 | Sandbox CRD created pod | Ready |
| 15 | SandboxClaim created pod from template | Ready |
| 16 | Direct connection bypassing proxy | Timeout (NetworkPolicy) |

## CI

The E2E workflow (`.github/workflows/e2e.yml`) runs on PRs touching `cmd/`, `internal/`, `Containerfile`, `go.mod`, `go.sum`, or `hack/kind/`. Also available via `workflow_dispatch`.

On failure, Warden logs, test server logs, and pod status are captured.

## Future Tests

The following require the `feat/multi-tenancy` branch to be merged:

- Multi-tenant mTLS with per-tenant policies and tenant isolation
- Warden-bridge sidecar (TLS mode)
- Tenant config hot reload
- HTTPS CONNECT with MITM interception (requires upstream TLS trust chain)

## Manual Testing

```bash
kubectl -n agent-sandbox exec -it test-agent -- sh

curl http://test-server.agent-sandbox.svc/get        # 200
curl http://test-server.agent-sandbox.svc/headers     # shows injected token
curl -X POST http://test-server.agent-sandbox.svc/post  # 403
curl http://test-server.agent-sandbox.svc/api/v1/resource  # 200
curl http://test-server.agent-sandbox.svc/api/v2/resource  # 403
curl http://example.com                               # 403
curl --noproxy '*' http://test-server.agent-sandbox.svc/get  # timeout
```

## Modifying Policies

```bash
vim hack/kind/manifests/warden-config.yaml
kubectl apply -f hack/kind/manifests/warden-config.yaml
kubectl -n agent-sandbox rollout restart deployment/warden
kubectl -n agent-sandbox wait --for=condition=Ready pod -l app=warden --timeout=60s
```

## CNI and NetworkPolicy

Calico replaces kind's default kindnet. The `192.168.0.0/16` pod subnet is isolated inside the kind Docker network. Warden's `deny_resolved_ips` is set to `169.254.0.0/16` only so the in-cluster test server (ClusterIP) is reachable through the proxy.

## Rebuilding After Code Changes

```bash
docker build -t warden:latest -f Containerfile .
kind load docker-image warden:latest --name warden-sandbox
kubectl -n agent-sandbox rollout restart deployment/warden
kubectl -n agent-sandbox wait --for=condition=Ready pod -l app=warden --timeout=60s
./hack/kind/test.sh
```

## Troubleshooting

**Sandbox pod Pending**: Check `kubectl -n agent-sandbox-system get pods`.

**Tests return 000**: Warden or test server not ready. Check pods and logs.

**Test 4 fails**: Secret not injected. Check `kubectl -n agent-sandbox logs -l app=warden | jq .`.

**Test 16 fails**: Calico not running. Check `kubectl -n kube-system get pods -l k8s-app=calico-node`.

**Image errors**: Both images use `imagePullPolicy: Never` — run `kind load docker-image` after building.
