#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLUSTER_NAME="warden-sandbox"
AGENT_SANDBOX_VERSION="v0.4.2"

info()  { echo "==> $*"; }
error() { echo "ERROR: $*" >&2; exit 1; }

for cmd in kind kubectl docker; do
  command -v "$cmd" >/dev/null || error "$cmd not found"
done

# Create kind cluster (skip if exists)
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  info "Cluster '$CLUSTER_NAME' already exists, reusing"
else
  info "Creating kind cluster '$CLUSTER_NAME'"
  kind create cluster --config "$SCRIPT_DIR/kind-config.yaml"
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

# Install Calico CNI for NetworkPolicy enforcement
if ! kubectl get daemonset -n kube-system calico-node &>/dev/null; then
  info "Installing Calico CNI"
  kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.3/manifests/calico.yaml

  info "Waiting for Calico to be ready"
  kubectl rollout status daemonset/calico-node -n kube-system --timeout=180s
  kubectl wait --for=condition=Ready pods -l k8s-app=calico-node \
    -n kube-system --timeout=180s
else
  info "Calico already installed, skipping"
fi

info "Waiting for nodes to be Ready"
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# Build container images
info "Building Warden container image"
docker build -t warden:latest -f "$REPO_ROOT/Containerfile" "$REPO_ROOT"

info "Building test server image"
docker build -t test-server:latest -f "$SCRIPT_DIR/testserver/Containerfile" "$SCRIPT_DIR/testserver"

# Load images into kind
info "Loading images into kind"
kind load docker-image warden:latest test-server:latest --name "$CLUSTER_NAME"

# Install Agent Sandbox CRDs + controller
info "Installing Agent Sandbox ${AGENT_SANDBOX_VERSION}"
kubectl apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml"

info "Installing Agent Sandbox extensions"
kubectl apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/extensions.yaml"

info "Waiting for Agent Sandbox controller"
kubectl wait --for=condition=Available deployment --all \
  -n agent-sandbox-system --timeout=120s

# Apply Warden manifests
info "Applying Warden manifests"
kubectl apply -f "$SCRIPT_DIR/manifests/namespace.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/warden-config.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/warden-secrets.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/warden-deployment.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/network-policies.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/test-server.yaml"

info "Waiting for Warden to be ready"
kubectl wait --for=condition=Ready pod -l app=warden \
  -n agent-sandbox --timeout=120s

info "Waiting for test server to be ready"
kubectl wait --for=condition=Ready pod -l app=test-server \
  -n agent-sandbox --timeout=120s

# Deploy multi-tenant Warden
info "Generating mTLS certificates"
"$SCRIPT_DIR/generate-certs.sh"

info "Deploying multi-tenant Warden"
kubectl apply -f "$SCRIPT_DIR/manifests/warden-mt-config.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/warden-mt-deployment.yaml"

info "Waiting for multi-tenant Warden to be ready"
kubectl wait --for=condition=Ready pod -l app=warden-mt \
  -n agent-sandbox --timeout=120s

# Create Sandbox resources
info "Creating test Sandbox"
kubectl apply -f "$SCRIPT_DIR/manifests/sandbox.yaml"

info "Creating SandboxTemplate and SandboxClaim"
kubectl apply -f "$SCRIPT_DIR/manifests/sandbox-template.yaml"

info "Creating multi-tenant agent sandboxes"
kubectl apply -f "$SCRIPT_DIR/manifests/sandbox-alpha.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/sandbox-beta.yaml"

info "Waiting for sandbox pods"
for i in $(seq 1 30); do
  if kubectl -n agent-sandbox get pod test-agent &>/dev/null; then
    break
  fi
  sleep 2
done
kubectl wait --for=condition=Ready pod test-agent \
  -n agent-sandbox --timeout=120s

# Wait for MT agent pods
for TENANT in alpha beta; do
  for i in $(seq 1 30); do
    if kubectl -n agent-sandbox get pod "agent-$TENANT" &>/dev/null; then
      break
    fi
    sleep 2
  done
done
kubectl wait --for=condition=Ready pod agent-alpha agent-beta \
  -n agent-sandbox --timeout=120s

info ""
info "============================================"
info "  Environment ready!"
info "============================================"
info ""
info "Cluster:  kind-${CLUSTER_NAME}"
info "NS:       agent-sandbox"
info ""
info "Test with:"
info "  ./hack/kind/test.sh"
info ""
info "Teardown:"
info "  ./hack/kind/teardown.sh"
