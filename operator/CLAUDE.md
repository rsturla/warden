# Warden Operator — Agent Guide

Kubernetes operator for declarative Warden proxy management. Separate Go module — core proxy has zero K8s dependencies.

## Quick Reference

```bash
make              # full pipeline: deps → generate → manifests → lint → test → build
make build        # dev build
make release      # stripped, static, CGO_ENABLED=0
make test         # unit + envtest (downloads API server binaries)
make test-race    # with race detector (CI default)
make fuzz         # fuzz targets (FUZZ_TIME=30s default)
make lint         # go vet + staticcheck
make generate     # controller-gen deepcopy
make manifests    # CRD + RBAC YAML generation
```

## Module

`github.com/rsturla/warden/operator` — separate `go.mod` with `replace` directive to import `pkg/api` from core module. Uses controller-runtime, K8s client-go, and envtest for testing.

## CRDs

API group: `wardenproxy.dev/v1alpha1`

### WardenProxy

Manages the Warden proxy lifecycle: Deployment, Service, ConfigMap, NetworkPolicies.

- Single-tenant: inline policies + secrets, auto CA, port 8080
- Multi-tenant: mTLS, tenant configs from shared ConfigMap, port 8443, cert-manager integration

### Tenant

Per-tenant configuration. Reconciles into:
- ConfigMap key (`{tenant-name}.yaml`) in the shared tenants ConfigMap
- cert-manager Certificate (CN = tenant name, client auth usage)

## Architecture

```
WardenProxy CR → operator → Deployment + Service + ConfigMap + NetworkPolicies
Tenant CR      → operator → ConfigMap entry + cert-manager Certificate
Pod (labeled)  → webhook  → injects warden-bridge sidecar + env vars
```

Operator and proxy are separate processes. They communicate through K8s primitives (ConfigMaps, Secrets). The proxy reads tenant configs via FileStore hot reload.

## Project Structure

```
cmd/operator/                  controller-manager entrypoint
api/v1alpha1/                  CRD types (Tenant, WardenProxy)
internal/
  controller/                  reconcilers
    tenant_controller.go       Tenant → ConfigMap + Certificate
    wardenproxy_controller.go  WardenProxy → Deployment + Service + ...
  webhook/
    pod_mutator.go             mutating webhook, injects bridge sidecar
config/
  crd/bases/                   generated CRD manifests
  rbac/                        generated RBAC role
  manager/                     operator Deployment
  webhook/                     MutatingWebhookConfiguration
  certmanager/                 webhook TLS certificate
  default/                     kustomize overlay (ties everything together)
  samples/                     example CRs
```

## Key Design Decisions

- **Separate Go module** — core proxy stays K8s-free (3 external deps)
- **Shared types in `pkg/api/`** — serialization contract between operator and proxy
- **ConfigMap as interface** — operator writes YAML, proxy reads via FileStore. No in-process coupling
- **Unstructured cert-manager** — cert-manager types accessed via `unstructured.Unstructured` to avoid importing the cert-manager Go module
- **Namespace-scoped CRDs** — supports multiple independent Warden deployments

## Testing

- **Webhook tests** — fake client, admission request construction, JSON patch verification
- **Serialization tests** — round-trip: CRD spec → YAML → `ParseTenantConfig` (uses core module)
- **Fuzz targets** — `FuzzSerializeTenantConfig` verifies YAML compatibility for arbitrary inputs
- **Envtest** — real API server + etcd, tests full reconciliation lifecycle
- `KUBEBUILDER_ASSETS` set automatically by Makefile via `setup-envtest`

## Code Conventions

Same as core module:
- **All interactions through Make**
- **No comments unless WHY non-obvious**
- **Errors**: wrap with `fmt.Errorf("context: %w", err)`
- **controller-runtime patterns** for reconcilers and webhooks
